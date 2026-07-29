// server/bridgeHandler.mjs — the HTTP binding for the Bridge Protocol (the Bridge protocol). ONE Lambda behind the
// /bridge routes. It parses method + path, loads the space state (membership + log) from the store, dispatches to the
// bridgeSpace SERVICE (which verifies signatures + capabilities + the epoch — CONTENT-BLIND, it never reads a body),
// persists, and returns JSON. A native party and an external party (someone else's agent over signed HTTPS) call the
// SAME routes.
//
// Auth is now SIGNED on every write, not deferred: SUBMIT by the entry's own signature (bridgeLog verifies it vs the
// membership pubkey); membership PUT by `verifyMembershipUpdate` (a CURRENT admit-holder signs; strictly-monotonic
// epoch; applied via an atomic compare-and-set → concurrent writers can't both land); CREATE by `verifyCreate` (the
// genesis is signed by the founder it names); DELETE by a TIME-BOUND `verifyDelete` (header-carried, expires). READ /
// MEMBERS / CHECKPOINT are content-blind or public. What remains OUT of scope here is a DISHONEST operator that
// equivocates (serves different heads to different parties) — caught by the server-signed checkpoints parties pin +
// gossip (see bridgeLog.checkpoint), which is designed, not yet built.
import { createService, read as svcRead, serviceSubmit, serviceCheckpoint } from './bridgeSpace.mjs'
import { verifyMembershipUpdate, verifyDelete, verifyCreate } from './bridgeLog.mjs'

const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'content-type', 'access-control-allow-methods': 'GET,POST,PUT,OPTIONS', 'content-type': 'application/json' }
const json = (statusCode, body) => ({ statusCode, headers: CORS, body: JSON.stringify(body || {}) })
const methodOf = (e) => (e && ((e.requestContext && e.requestContext.http && e.requestContext.http.method) || e.httpMethod)) || 'GET'
const pathOf = (e) => (e && (e.rawPath || (e.requestContext && e.requestContext.http && e.requestContext.http.path) || e.path)) || ''
const parseBody = (e) => { try { const v = JSON.parse((e && e.body) || '{}'); return v && typeof v === 'object' ? v : {} } catch { return {} } } // coerce null/scalars to {} — a JSON `null` body must be a clean 400, never a 500
// The delete authorization rides in a HEADER (sturdier than a DELETE body some proxies strip; out of the URL/logs):
// base64url(JSON({party, sig, ts})). API-Gateway v2 lowercases header names.
const parseDeleteAuth = (e) => { try { const h = (e && e.headers && (e.headers['x-bridge-authorization'] || e.headers['X-Bridge-Authorization'])) || ''; return h ? JSON.parse(Buffer.from(String(h), 'base64url').toString('utf8')) : {} } catch { return {} } }

// A service instance backed by the loaded state; the ops mutate the returned {membership, log} which we persist.
const serviceOf = (space, state, serverKey) => ({ space, membership: state.membership, log: Array.isArray(state.log) ? state.log : [], serverKey })

/** The pure handler. deps: { store: { get(space)→{membership,log}|null, putMembership(space,m), putLog(space,log) },
 *  serverKey: {pub,priv} } — injected so it's testable without AWS. */
export async function handleBridgeHttp(event, deps = {}) {
  const method = methodOf(event)
  if (method === 'OPTIONS') return json(204, {})
  const { store, serverKey } = deps
  if (!store || !serverKey) return json(500, { error: 'no_store' })

  const path = pathOf(event).replace(/\/+$/, '') // trim trailing slash
  // POST /bridge/spaces  — found a space (store the initial membership record; the founder holds the key)
  if (method === 'POST' && /\/bridge\/spaces$/.test(path)) {
    const m = parseBody(event)
    if (!m.space || !Array.isArray(m.members)) return json(400, { error: 'bad_membership' })
    if (await store.get(m.space)) return json(409, { error: 'exists' }) // first-create-wins: an existing id is never re-founded
    if (!(await verifyCreate(m))) return json(403, { error: 'unauthorized_create' }) // the genesis record must be SIGNED by the founder it names
    await store.putMembership(m.space, m)
    await store.putLog(m.space, [])
    return json(201, { space: m.space })
  }

  // /bridge/spaces/{space}/...
  const mm = path.match(/\/bridge\/spaces\/([^/]+)(\/(members|entries|checkpoint))?$/)
  if (!mm) return json(404, { error: 'not_found' })
  const space = decodeURIComponent(mm[1])
  const sub = mm[3] || 'members'
  if (method === 'DELETE' && !mm[3]) { // teardown — disposable self-test litter only (sp-ci-*), NEVER a real space
    if (!/^sp-ci-/.test(space)) return json(403, { error: 'protected' }) // hard boundary: a real space is not deletable here
    const st = await store.get(space)
    if (!st) return json(204, {}) // already gone — idempotent
    // The authorization { party, sig, ts } rides in the x-bridge-authorization HEADER (not the URL → not logged) and is time-bound.
    if (!(await verifyDelete(st.membership, parseDeleteAuth(event), { now: nowMs() }))) return json(403, { error: 'unauthorized_delete' })
    if (store.delete) await store.delete(space)
    return json(204, {})
  }
  const state = await store.get(space)
  if (!state) return json(404, { error: 'no_space' })
  const svc = serviceOf(space, state, serverKey)

  if (sub === 'members') {
    if (method === 'GET') return json(200, svc.membership) // MEMBERS (public record incl. each member's sealed grant)
    if (method === 'PUT') { // ADMIT / REVOKE — verify the update is AUTHORIZED (signed by a current admit-holder), not just stored
      const m = parseBody(event)
      if (m.space !== space || !Array.isArray(m.members)) return json(400, { error: 'bad_membership' })
      if (!(await verifyMembershipUpdate(state.membership, m))) return json(403, { error: 'unauthorized_update' })
      // ATOMIC compare-and-set on the epoch: apply only if the stored head is STILL the one we verified against. So two
      // genuinely-concurrent writes at the same next epoch can't BOTH land (read-check-write would let last-write-win and
      // silently clobber a revocation); the loser gets 409 and must re-base on the new head + resubmit at the next epoch.
      if (!(await store.putMembership(space, m, { ifEpoch: state.membership.epoch }))) return json(409, { error: 'conflict' })
      return json(200, m)
    }
  }
  if (sub === 'entries') {
    if (method === 'GET') { // READ — sealed delta (content-blind; a read teaches the server nothing)
      const cursor = Number((event.queryStringParameters && event.queryStringParameters.cursor) || 0) || 0
      return json(200, svcRead(svc, cursor))
    }
    if (method === 'POST') { // SUBMIT — bridgeSpace verifies member · submit-cap · epoch · signature, then chains
      const r = await serviceSubmit(svc, parseBody(event), { now: nowMs() })
      if (!r.ok) return json(r.error === 'not_a_member' || r.error === 'no_submit_cap' ? 403 : 400, { error: r.error })
      await store.putLog(space, r.svc.log)
      return json(201, { seq: r.seq })
    }
  }
  if (sub === 'checkpoint' && method === 'GET') return json(200, await serviceCheckpoint(svc, { now: nowMs() }))
  return json(405, { error: 'method_not_allowed' })
}

const nowMs = () => { try { return Date.now() } catch { return 0 } }

// ── default DynamoDB store (lazily constructed) + the Lambda entry — wired at deploy (Cut 4b) ────────────────────────
let _doc, _serverKey
async function docClient() {
  if (_doc) return _doc
  const { DynamoDBClient } = await import('@aws-sdk/client-dynamodb')
  const { DynamoDBDocumentClient } = await import('@aws-sdk/lib-dynamodb')
  return (_doc = DynamoDBDocumentClient.from(new DynamoDBClient({})))
}
function dynamoStore(table = process.env.BRIDGE_TABLE || '') {
  const key = (space, sk) => ({ space, sk })
  return {
    async get(space) {
      if (!table) return null
      const { GetCommand } = await import('@aws-sdk/lib-dynamodb')
      const doc = await docClient()
      const m = (await doc.send(new GetCommand({ TableName: table, Key: key(space, 'membership') }))).Item
      if (!m) return null
      const l = (await doc.send(new GetCommand({ TableName: table, Key: key(space, 'log') }))).Item
      return { membership: m.membership, log: (l && l.log) || [] }
    },
    async putMembership(space, membership, opts = {}) {
      const { PutCommand } = await import('@aws-sdk/lib-dynamodb')
      const params = { TableName: table, Item: { ...key(space, 'membership'), membership } }
      if (opts.ifEpoch !== undefined) { // atomic compare-and-set: overwrite only if the stored head is STILL at ifEpoch
        params.ConditionExpression = '#m.#e = :expected'
        params.ExpressionAttributeNames = { '#m': 'membership', '#e': 'epoch' }
        params.ExpressionAttributeValues = { ':expected': opts.ifEpoch }
      }
      try { await (await docClient()).send(new PutCommand(params)); return true }
      catch (e) { if (e && e.name === 'ConditionalCheckFailedException') return false; throw e } // a concurrent writer advanced the epoch → the caller re-bases
    },
    async putLog(space, log) { const { PutCommand } = await import('@aws-sdk/lib-dynamodb'); await (await docClient()).send(new PutCommand({ TableName: table, Item: { ...key(space, 'log'), log } })) },
    async delete(space) { if (!table) return; const { DeleteCommand } = await import('@aws-sdk/lib-dynamodb'); const doc = await docClient(); await doc.send(new DeleteCommand({ TableName: table, Key: key(space, 'membership') })); await doc.send(new DeleteCommand({ TableName: table, Key: key(space, 'log') })) },
  }
}
// The server/checkpoint key is resolved once at cold start from SSM (BRIDGE_SERVER_KEY_PARAM) — stable across invocations.
async function serverKey() {
  if (_serverKey) return _serverKey
  const param = process.env.BRIDGE_SERVER_KEY_PARAM
  if (!param) { const { genServerKey } = await import('./bridgeLog.mjs'); return (_serverKey = await genServerKey()) } // dev fallback (ephemeral)
  const { SSMClient, GetParameterCommand } = await import('@aws-sdk/client-ssm')
  const r = await new SSMClient({}).send(new GetParameterCommand({ Name: param, WithDecryption: true }))
  return (_serverKey = JSON.parse(r.Parameter.Value))
}

export async function handler(event) {
  return handleBridgeHttp(event, { store: dynamoStore(), serverKey: await serverKey() })
}
