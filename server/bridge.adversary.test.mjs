// server/bridge.adversary.test.mjs — the HOSTILE-client suite. Our tests used to drive the server through our own
// well-behaved admit()/putMembers(), which can only emit VALID data — so "does the server refuse a hostile write?" was
// never asked, and an unauthenticated membership upgrade slipped through. This file constructs malformed/forged requests
// DIRECTLY (bypassing the honest client) and fires them at every mutating route, organized as an invariant × attack
// grid. Each negative asserts the specific ERROR (not just the status — two guards can share a 403 and mask each other),
// and every invariant carries a POSITIVE control so a refusal proves the guard, not a broken space.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { genPartyIdentity, publicIdentity, openSpace, admit } from './bridgeMembership.mjs'
import { makeEntry, makeCoSignedEntry, signMembership, signDelete } from './bridgeLog.mjs'
import { genServerKey } from './bridgeLog.mjs'
import { handleBridgeHttp } from './bridgeHandler.mjs'

function memStore() {
  const map = new Map()
  return {
    async get(s) { return map.has(s + ':m') ? { membership: map.get(s + ':m'), log: map.get(s + ':l') || [] } : null },
    async putMembership(s, x, opts = {}) { if (opts.ifEpoch !== undefined) { const cur = map.get(s + ':m'); if (!cur || cur.epoch !== opts.ifEpoch) return false } map.set(s + ':m', x); return true },
    async putLog(s, x) { map.set(s + ':l', x) },
    async delete(s) { map.delete(s + ':m'); map.delete(s + ':l') },
  }
}
const deps = { store: memStore(), serverKey: await genServerKey() }
const ev = (method, path, body, query, headers) => ({ requestContext: { http: { method, path } }, rawPath: path, headers, body: body ? JSON.stringify(body) : undefined, queryStringParameters: query })
const call = async (method, path, body, query, headers) => { const r = await handleBridgeHttp(ev(method, path, body, query, headers), deps); return { status: r.statusCode, error: JSON.parse(r.body).error } }
const BODY = { v: 1, alg: 'gcm', iv: 'AAAA', ct: 'AAAA' } // an opaque sealed blob — submit is content-blind, never opens it

const A = await genPartyIdentity()        // founder — all caps
const O = await genPartyIdentity()        // read only (the assistant)
const G = await genPartyIdentity()        // read + submit (the human)
const stranger = await genPartyIdentity()  // never admitted

// Found a fresh space per block (isolated state) with the demo's shape: A founder, O read-only, G read+submit.
async function setup(tag) {
  const space = tag
  let m = await openSpace(space, A)
  assert.equal((await call('POST', '/bridge/spaces', m)).status, 201)
  m = await admit(m, A, publicIdentity(O), { caps: ['read'] })
  m = await admit(m, A, publicIdentity(G), { caps: ['read', 'submit'] })
  assert.equal((await call('PUT', `/bridge/spaces/${space}/members`, m)).status, 200)
  return { space, m }
}
const P = (space) => `/bridge/spaces/${space}`
// craft a membership signed by `signer` (the adversary or the admitter) over {space,epoch,members}
const craft = async (space, epoch, members, signer) => { const n = { space, epoch, members }; n.auth = { party: signer.id, sig: await signMembership(signer.sign.priv, n) }; return n }
const withCap = (m, party, caps) => m.members.map((x) => (x.party === party ? { ...x, caps } : x))

// ── INVARIANT 1 · CONFINEMENT — a read-only party can neither post nor be promoted (the hole we shipped) ──────────────
test('confinement: a read-only party can neither post nor be promoted (by anyone but a current admit-holder)', async () => {
  const { space, m } = await setup('sp-adv-conf')
  const e = m.epoch
  const up = withCap(m, O.id, ['read', 'submit']) // "upgrade the assistant"

  assert.deepEqual(await call('POST', `${P(space)}/entries`, await makeEntry(O, { space, epoch: e, body: BODY })), { status: 403, error: 'no_submit_cap' }, 'O cannot post')
  assert.deepEqual(await call('PUT', `${P(space)}/members`, await craft(space, e + 1, up, stranger)), { status: 403, error: 'unauthorized_update' }, 'an outsider cannot upgrade O')
  assert.deepEqual(await call('PUT', `${P(space)}/members`, await craft(space, e + 1, up, O)), { status: 403, error: 'unauthorized_update' }, 'O cannot upgrade itself')
  assert.deepEqual(await call('PUT', `${P(space)}/members`, await craft(space, e + 1, withCap(m, G.id, ['read', 'submit', 'admit']), G)), { status: 403, error: 'unauthorized_update' }, 'G (submit) cannot grant itself admit')
  assert.deepEqual(await call('PUT', `${P(space)}/members`, { space, epoch: e + 1, members: up }), { status: 403, error: 'unauthorized_update' }, 'an unsigned upgrade is refused')

  // POSITIVE: the ONE authorized path — a current admit-holder (A) re-caps O — is accepted.
  assert.equal((await call('PUT', `${P(space)}/members`, await craft(space, e + 1, up, A))).status, 200, 'A (admit) MAY re-cap O')
})

// ── INVARIANT 2 · ATTRIBUTION — every entry is signed by its party; a co-signature binds BOTH, over the same core ─────
test('attribution: forged, tampered, or non-member-drafted entries are refused; a genuine co-signed crossing is accepted', async () => {
  const { space, m } = await setup('sp-adv-attr')
  const e = m.epoch

  const asStranger = await makeEntry(stranger, { space, epoch: e, body: BODY })
  assert.deepEqual(await call('POST', `${P(space)}/entries`, asStranger), { status: 403, error: 'not_a_member' }, 'a non-member is refused')
  assert.deepEqual(await call('POST', `${P(space)}/entries`, { ...asStranger, party: A.id }), { status: 400, error: 'bad_signature' }, 'claiming A but signing as stranger fails')
  const good = await makeEntry(A, { space, epoch: e, body: BODY })
  assert.deepEqual(await call('POST', `${P(space)}/entries`, { ...good, body: { ...BODY, ct: 'SWAPPED' } }), { status: 400, error: 'bad_signature' }, 'a body swapped after signing fails')
  assert.deepEqual(await call('POST', `${P(space)}/entries`, await makeCoSignedEntry(G, stranger, { space, epoch: e, body: BODY })), { status: 400, error: 'bad_signature' }, 'a co-signature naming a non-member drafter fails')

  // POSITIVE: the read-only assistant DRAFTS, the human APPROVES — both sigs verify → it crosses.
  assert.equal((await call('POST', `${P(space)}/entries`, await makeCoSignedEntry(G, O, { space, epoch: e, body: BODY }))).status, 201, 'a genuine co-signed crossing is accepted')
})

// ── INVARIANT 3 · CONTEXT BINDING — an entry is bound to its space + epoch and is single-use ─────────────────────────
test('context binding: replay, cross-space, and old-epoch entries are refused; a fresh entry each way is accepted', async () => {
  const one = await setup('sp-adv-ctx'); const two = await setup('sp-adv-ctx2')
  const e = one.m.epoch
  const entry = await makeCoSignedEntry(G, O, { space: one.space, epoch: e, body: BODY })

  assert.equal((await call('POST', `${P(one.space)}/entries`, entry)).status, 201, 'first crossing accepted')
  assert.deepEqual(await call('POST', `${P(one.space)}/entries`, entry), { status: 400, error: 'replay' }, 'the same signed entry cannot be re-appended')
  assert.deepEqual(await call('POST', `${P(two.space)}/entries`, entry), { status: 400, error: 'wrong_space' }, "one's entry cannot be replayed into two")
  // POSITIVE: a fresh entry NATIVE to two is accepted (so wrong_space is specific, not "two is broken").
  assert.equal((await call('POST', `${P(two.space)}/entries`, await makeCoSignedEntry(G, O, { space: two.space, epoch: two.m.epoch, body: BODY }))).status, 201, 'a fresh entry native to two is accepted')

  // bump one's epoch (A admits a new party), then an entry at the OLD epoch is refused; a fresh one at the NEW epoch is accepted.
  const bumped = await admit(one.m, A, publicIdentity(await genPartyIdentity()), { caps: ['read'] })
  assert.equal((await call('PUT', `${P(one.space)}/members`, bumped)).status, 200)
  assert.deepEqual(await call('POST', `${P(one.space)}/entries`, await makeCoSignedEntry(G, O, { space: one.space, epoch: e, body: BODY })), { status: 400, error: 'wrong_epoch' }, 'an old-epoch entry is refused')
  assert.equal((await call('POST', `${P(one.space)}/entries`, await makeCoSignedEntry(G, O, { space: one.space, epoch: bumped.epoch, body: BODY }))).status, 201, 'a fresh entry at the new epoch is accepted')
})

// ── INVARIANT 4 · GOVERNED MEMBERSHIP + TEARDOWN — epoch monotonic; a real space is undeletable; teardown is signed ───
test('governance: epoch rollback refused; a real space is undeletable even by its founder; teardown needs an admit signature', async () => {
  const { space, m } = await setup('sp-adv-gov')
  const e = m.epoch
  // epoch rollback: even A's signature at the same or an earlier epoch is not a successor.
  assert.deepEqual(await call('PUT', `${P(space)}/members`, await craft(space, e, m.members, A)), { status: 403, error: 'unauthorized_update' }, 'same epoch is not a successor')
  assert.deepEqual(await call('PUT', `${P(space)}/members`, await craft(space, e - 1, m.members, A)), { status: 403, error: 'unauthorized_update' }, 'an earlier epoch is a rollback')
  // POSITIVE: A admits a new member (a genuine successor) → accepted.
  assert.equal((await call('PUT', `${P(space)}/members`, await admit(m, A, publicIdentity(await genPartyIdentity())))).status, 200, 'a genuine admit is a successor')

  // teardown — the authorization { party, sig, ts } rides in the x-bridge-authorization HEADER and is time-bound.
  const delHdr = async (actor, sp) => { const ts = Date.now(); return { 'x-bridge-authorization': Buffer.from(JSON.stringify({ party: actor.id, sig: await signDelete(actor.sign.priv, sp, ts), ts })).toString('base64url') } }
  // a REAL (non sp-ci-*) space is undeletable HERE even WITH a valid founder signature (namespace boundary).
  assert.deepEqual(await call('DELETE', P(space), undefined, undefined, await delHdr(A, space)), { status: 403, error: 'protected' }, 'a real space is undeletable here even by its founder')
  assert.equal((await call('GET', `${P(space)}/members`)).status, 200, 'and it still exists')

  // within the disposable sp-ci-* namespace, teardown still needs a current admit-holder's signature.
  let ci = await openSpace('sp-ci-adv', A); await call('POST', '/bridge/spaces', ci)
  ci = await admit(ci, A, publicIdentity(G), { caps: ['read', 'submit'] }); await call('PUT', '/bridge/spaces/sp-ci-adv/members', ci)
  assert.deepEqual(await call('DELETE', '/bridge/spaces/sp-ci-adv'), { status: 403, error: 'unauthorized_delete' }, 'no signature → unauthorized_delete')
  assert.deepEqual(await call('DELETE', '/bridge/spaces/sp-ci-adv', undefined, undefined, await delHdr(G, 'sp-ci-adv')), { status: 403, error: 'unauthorized_delete' }, 'G (no admit) cannot tear it down')
  assert.equal((await call('DELETE', '/bridge/spaces/sp-ci-adv', undefined, undefined, await delHdr(A, 'sp-ci-adv'))).status, 204, 'the founder (admit) tears it down')
})
