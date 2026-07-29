import { test } from 'node:test'
import assert from 'node:assert/strict'
import { genPartyIdentity, publicIdentity, openSpace, admit } from './bridgeMembership.mjs'
import { genServerKey, verifyCheckpoint, chainMatchesCheckpoint, makeEntry, signMembership, signDelete } from './bridgeLog.mjs'
import { createService, makePartyEntry } from './bridgeSpace.mjs'
import { handleBridgeHttp } from './bridgeHandler.mjs'

// an in-memory store so the HTTP handler runs without AWS (the DynamoDB store mirrors this shape).
function memStore() {
  const m = new Map()
  return {
    async get(s) { return m.has(s + ':membership') ? { membership: m.get(s + ':membership'), log: m.get(s + ':log') || [] } : null },
    async putMembership(s, x, opts = {}) { if (opts.ifEpoch !== undefined) { const cur = m.get(s + ':membership'); if (!cur || cur.epoch !== opts.ifEpoch) return false } m.set(s + ':membership', x); return true },
    async putLog(s, x) { m.set(s + ':log', x) },
    async delete(s) { m.delete(s + ':membership'); m.delete(s + ':log') },
  }
}
const server = await genServerKey()
const store = memStore()
const deps = { store, serverKey: server }
const ev = (method, path, body, query, headers) => ({ requestContext: { http: { method, path } }, rawPath: path, headers, body: body ? JSON.stringify(body) : undefined, queryStringParameters: query })
const call = async (method, path, body, query, headers) => { const r = await handleBridgeHttp(ev(method, path, body, query, headers), deps); return { status: r.statusCode, body: JSON.parse(r.body) } }
// the delete authorization as the x-bridge-authorization HEADER (base64url(JSON({party,sig,ts})))
const delHdr = async (actor, space, { ts = Date.now() } = {}) => ({ 'x-bridge-authorization': Buffer.from(JSON.stringify({ party: actor.id, sig: await signDelete(actor.sign.priv, space, ts), ts })).toString('base64url') })

const A = await genPartyIdentity() // founder
const X = await genPartyIdentity() // external party
const stranger = await genPartyIdentity()

test('the /bridge binding runs the full flow: found → admit → submit → read → checkpoint', async () => {
  // FOUND — A builds the initial membership record (party-side) and POSTs it.
  let m = await openSpace('sp-http', A)
  assert.equal((await call('POST', '/bridge/spaces', m)).status, 201)
  // ADMIT X (party-side re-key) → PUT the new record.
  m = await admit(m, A, publicIdentity(X))
  assert.equal((await call('PUT', '/bridge/spaces/sp-http/members', m)).status, 200)

  // the current state svc (both clients would GET /members to learn this).
  const svc = createService('sp-http', m, server)
  // SUBMIT — X seals+signs an entry client-side and POSTs it.
  const xEntry = await makePartyEntry(svc, X, { content: 'external party checking in', kind: 'load', actor: 'agent' })
  const r1 = await call('POST', '/bridge/spaces/sp-http/entries', xEntry)
  assert.equal(r1.status, 201); assert.equal(r1.body.seq, 0)
  // SUBMIT — A too (clientHeadSeq now 1 → build against the current log length; the server re-chains regardless).
  const svc1 = { ...svc, log: [{ seq: 0 }] }
  const aEntry = await makePartyEntry(svc1, A, { content: 'native party replying', kind: 'post', actor: 'human' })
  assert.equal((await call('POST', '/bridge/spaces/sp-http/entries', aEntry)).status, 201)

  // READ — the sealed delta (ciphertext bodies).
  const rd = await call('GET', '/bridge/spaces/sp-http/entries', undefined, { cursor: '0' })
  assert.equal(rd.status, 200); assert.equal(rd.body.entries.length, 2)
  assert.equal(rd.body.entries[0].party, X.id); assert.equal(rd.body.entries[1].party, A.id)
  assert.equal(JSON.stringify(rd.body.entries).includes('checking in'), false, 'stored bodies are ciphertext (content-blind)')

  // MEMBERS.
  const mem = await call('GET', '/bridge/spaces/sp-http/members')
  assert.equal(mem.status, 200); assert.equal(mem.body.members.length, 2)

  // CHECKPOINT — server-signed, verifies + matches the served log.
  const cp = await call('GET', '/bridge/spaces/sp-http/checkpoint')
  assert.equal(cp.status, 200)
  assert.equal(await verifyCheckpoint(server.pub, cp.body), true)
  const served = (await call('GET', '/bridge/spaces/sp-http/entries', undefined, { cursor: '0' })).body.entries
  assert.equal(await chainMatchesCheckpoint(served, cp.body), true)
})

test('governance: a stranger cannot submit; a bad signature is rejected', async () => {
  let m = await openSpace('sp-http-2', A)
  await call('POST', '/bridge/spaces', m)
  m = await admit(m, A, publicIdentity(X))
  await call('PUT', '/bridge/spaces/sp-http-2/members', m)
  const svc = createService('sp-http-2', m, server)
  // a stranger (never admitted) can't even build an entry (no epoch key) — but forge a shaped one → server rejects.
  const forged = await makeEntry(stranger, { space: 'sp-http-2', kind: 'post', actor: 'agent', epoch: m.epoch, body: { v: 1, alg: 'gcm', iv: 'x', ct: 'x' }, clientHeadSeq: 0 })
  assert.equal((await call('POST', '/bridge/spaces/sp-http-2/entries', forged)).status, 403) // not_a_member
  // a member's entry with a tampered body → bad signature → 400.
  const good = await makePartyEntry(svc, X, { content: 'ok', kind: 'post' })
  assert.equal((await call('POST', '/bridge/spaces/sp-http-2/entries', { ...good, body: { ...good.body, ct: 'TAMPERED' } })).status, 400)
})

test('404 on an unknown space; 409 on a duplicate found', async () => {
  assert.equal((await call('GET', '/bridge/spaces/nope/members')).status, 404)
  const m = await openSpace('sp-http-3', A)
  assert.equal((await call('POST', '/bridge/spaces', m)).status, 201)
  assert.equal((await call('POST', '/bridge/spaces', m)).status, 409)
})

test('create is a SIGNED write: a founder-signed genesis is accepted, unsigned/forged is refused, re-create is 409', async () => {
  const good = await openSpace('sp-http-create', A) // openSpace signs the genesis with the founder's key
  assert.equal((await call('POST', '/bridge/spaces', good)).status, 201, 'a founder-signed create is accepted')
  assert.equal((await call('POST', '/bridge/spaces', good)).status, 409, 're-creating an existing id is refused (first-create-wins)')
  // an UNSIGNED genesis (auth stripped) → 403 unauthorized_create
  const { auth, ...unsigned } = await openSpace('sp-http-create-2', A)
  assert.equal((await call('POST', '/bridge/spaces', unsigned)).status, 403, 'an unsigned create is refused')
  // a genesis naming A as founder but signed by a NON-MEMBER (stranger) → 403: you can't found a space in another's name
  const forged = await openSpace('sp-http-create-3', A)
  forged.auth = { party: stranger.id, sig: await signMembership(stranger.sign.priv, forged) }
  assert.equal((await call('POST', '/bridge/spaces', forged)).status, 403, 'a create signed by a non-member is refused')
  assert.equal((await call('GET', '/bridge/spaces/sp-http-create-3/members')).status, 404, 'and nothing was stored')
})

test('authorization: an unauthorized membership PUT and an unsigned DELETE are refused at the HTTP layer', async () => {
  let m = await openSpace('sp-ci-http', A) // sp-ci-* so DELETE's namespace guard permits it
  await call('POST', '/bridge/spaces', m)
  m = await admit(m, A, publicIdentity(X)) // X: read+submit, NOT admit
  assert.equal((await call('PUT', '/bridge/spaces/sp-ci-http/members', m)).status, 200, 'a genuine admit is authorized')

  // craft a record upgrading X to admit, signed by X (who lacks admit) → refused; unsigned → refused. Assert the REASON
  // (unauthorized_update), not merely the status — two guards can both return 403, masking each other's removal.
  const upgraded = m.members.map((y) => (y.party === X.id ? { ...y, caps: ['read', 'submit', 'admit'] } : y))
  const forged = { space: 'sp-ci-http', epoch: m.epoch + 1, members: upgraded }
  forged.auth = { party: X.id, sig: await signMembership(X.sign.priv, forged) }
  const rSelf = await call('PUT', '/bridge/spaces/sp-ci-http/members', forged)
  assert.equal(rSelf.status, 403); assert.equal(rSelf.body.error, 'unauthorized_update', 'X cannot self-upgrade (no admit cap)')
  const rUnsigned = await call('PUT', '/bridge/spaces/sp-ci-http/members', { space: 'sp-ci-http', epoch: m.epoch + 1, members: upgraded })
  assert.equal(rUnsigned.status, 403); assert.equal(rUnsigned.body.error, 'unauthorized_update', 'an unsigned update is refused')

  // DELETE — the authorization { party, sig, ts } rides in the x-bridge-authorization HEADER and is time-bound.
  // (1) the namespace boundary blocks a REAL space even WITH a valid founder signature (else its removal is masked by
  //     the signature guard). Without this guard the founder-signed delete would succeed (204) → this test goes red.
  const delReal = await call('DELETE', '/bridge/spaces/sp-http', undefined, undefined, await delHdr(A, 'sp-http'))
  assert.equal(delReal.status, 403); assert.equal(delReal.body.error, 'protected', 'a real space is undeletable here even by its founder')
  assert.equal((await call('GET', '/bridge/spaces/sp-http/members')).status, 200, 'and it still exists')
  // (2) within the disposable namespace, teardown still needs a valid admit-holder signature.
  const delNoSig = await call('DELETE', '/bridge/spaces/sp-ci-http')
  assert.equal(delNoSig.status, 403); assert.equal(delNoSig.body.error, 'unauthorized_delete', 'no signature → unauthorized_delete')
  const delX = await call('DELETE', '/bridge/spaces/sp-ci-http', undefined, undefined, await delHdr(X, 'sp-ci-http'))
  assert.equal(delX.status, 403); assert.equal(delX.body.error, 'unauthorized_delete', 'X (no admit) cannot delete')
  // (2b) a STALE authorization (old ts, validly signed by the founder) is refused — the token expires, it isn't permanent.
  const stale = await call('DELETE', '/bridge/spaces/sp-ci-http', undefined, undefined, await delHdr(A, 'sp-ci-http', { ts: Date.now() - 3600_000 }))
  assert.equal(stale.status, 403); assert.equal(stale.body.error, 'unauthorized_delete', 'an expired delete authorization is refused')
  // (3) the founder (admit-holder) tears the disposable space down — the positive control.
  assert.equal((await call('DELETE', '/bridge/spaces/sp-ci-http', undefined, undefined, await delHdr(A, 'sp-ci-http'))).status, 204, 'the founder (admit) tears it down')
  assert.equal((await call('GET', '/bridge/spaces/sp-ci-http/members')).status, 404, 'and it is gone')
})

test('membership PUT is an atomic compare-and-set: a lost CAS is a 409 conflict (concurrent writers can not both land)', async () => {
  // (1) the store CAS primitive: overwrite ONLY when the stored epoch still matches what we read.
  const base = memStore()
  await base.putMembership('sp-cas', { space: 'sp-cas', epoch: 1, members: [] })
  assert.equal(await base.putMembership('sp-cas', { space: 'sp-cas', epoch: 2, members: [] }, { ifEpoch: 1 }), true, 'CAS matches → applied')
  assert.equal(await base.putMembership('sp-cas', { space: 'sp-cas', epoch: 3, members: [] }, { ifEpoch: 1 }), false, 'CAS stale (stored is 2, not 1) → refused')
  // (2) the handler turns a lost CAS into 409 — a concurrent writer advanced the epoch between our read and our write.
  const b2 = memStore()
  const casLoser = { ...b2, async putMembership(s, x, opts) { if (opts && opts.ifEpoch !== undefined) return false; return b2.putMembership(s, x) } }
  const deps2 = { store: casLoser, serverKey: server }
  let m = await openSpace('sp-cas2', A)
  assert.equal((await handleBridgeHttp(ev('POST', '/bridge/spaces', m), deps2)).statusCode, 201)
  m = await admit(m, A, publicIdentity(X))
  assert.equal((await handleBridgeHttp(ev('PUT', '/bridge/spaces/sp-cas2/members', m), deps2)).statusCode, 409, 'a lost compare-and-set is a 409 conflict, not a silent overwrite')
})

test('the delete token has a DEFINED expiry: just inside the window is accepted, just past it is refused', async () => {
  const mk = async (name) => { await call('POST', '/bridge/spaces', await openSpace(name, A)); return name }
  const inWin = await mk('sp-ci-edge-in')
  assert.equal((await call('DELETE', `/bridge/spaces/${inWin}`, undefined, undefined, await delHdr(A, inWin, { ts: Date.now() - 570000 }))).status, 204, 'a token ~9.5min old (inside the 10min window) is accepted')
  const out = await mk('sp-ci-edge-out')
  const r = await call('DELETE', `/bridge/spaces/${out}`, undefined, undefined, await delHdr(A, out, { ts: Date.now() - 630000 }))
  assert.equal(r.status, 403); assert.equal(r.body.error, 'unauthorized_delete', 'a token ~10.5min old (past the window) is refused')
})
