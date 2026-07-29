// agent/bridge.revocation.test.mjs — revocation is where these schemes break, and it was tested only as pure membership
// logic (bridgeMembership.test), never as a SERVER-governed operation. This drives revoke() through the real HTTP
// handler and writes the attack a reviewer reaches for once the obvious PUT is closed: the PRE-SIGNED TRANSITION — a
// party signs a membership while it holds admit, admit is then revoked, and it submits the stale-but-valid record. It is
// refused because authority is re-checked against the CURRENT head at apply time (not "some record"), and because the
// epoch is monotonic. Also pins the deliberate successor policy: no-lockout, no rollback, no same-epoch fork.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { genPartyIdentity, publicIdentity, openSpace, admit, revoke } from './bridgeMembership.mjs'
import { makeEntry, signMembership, genServerKey } from './bridgeLog.mjs'
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
const ev = (method, path, body, query) => ({ requestContext: { http: { method, path } }, rawPath: path, body: body === undefined ? undefined : JSON.stringify(body), queryStringParameters: query })
const call = async (method, path, body, query) => { const r = await handleBridgeHttp(ev(method, path, body, query), deps); return { status: r.statusCode, body: JSON.parse(r.body) } }
const BODY = { v: 1, alg: 'gcm', iv: 'AAAA', ct: 'AAAA' }

const A = await genPartyIdentity() // founder — all caps (admit + revoke)
const G = await genPartyIdentity()
const O = await genPartyIdentity()
const put = (space, m) => call('PUT', `/bridge/spaces/${space}/members`, m)
const post = (space, e) => call('POST', `/bridge/spaces/${space}/entries`, e)
const members = (space) => call('GET', `/bridge/spaces/${space}/members`)
// found a space and PUT each admit as its own committed epoch (as a real client does)
async function found(space, admits = []) {
  let m = await openSpace(space, A); await call('POST', '/bridge/spaces', m)
  for (const [who, caps] of admits) { m = await admit(m, A, publicIdentity(who), { caps }); assert.equal((await put(space, m)).status, 200) }
  return m
}
const pubMember = (idn, caps) => ({ party: idn.id, boxPub: idn.box.pub, signPub: idn.sign.pub, caps, keyGrants: {} })
// a raw membership record signed by an arbitrary party (the adversary or the admitter) — no re-key, to isolate authz
const craftBy = async (signer, space, epoch, ms) => ({ space, epoch, members: ms, auth: { party: signer.id, sig: await signMembership(signer.sign.priv, { space, epoch, members: ms }) } })

test('revoke is server-authorized; the removed party can no longer submit', async () => {
  const space = 'sp-rev-basic'
  let m = await found(space, [[G, ['read', 'submit']]]) // epoch 1: A, G
  assert.equal((await post(space, await makeEntry(G, { space, epoch: m.epoch, body: BODY }))).status, 201, 'G submits while a member')
  m = await revoke(m, A, G.id) // epoch 2: A only
  assert.equal((await put(space, m)).status, 200, 'A (holds revoke) authorizes the revoke')
  assert.equal((await members(space)).body.members.some((x) => x.party === G.id), false, 'G is gone from the public record')
  assert.equal((await post(space, await makeEntry(G, { space, epoch: m.epoch, body: BODY }))).status, 403, 'the revoked party cannot submit')
})

test('PRE-SIGNED TRANSITION attack: a record signed while holding admit is refused once that admit is revoked', async () => {
  const space = 'sp-rev-presign'
  let m = await found(space, [[G, ['read', 'submit', 'admit']]]) // epoch 1: A, G(admit)
  const e1 = m.epoch
  const puppet = await genPartyIdentity() // G's back-door: a second admit it controls
  const hostile = [...m.members, pubMember(puppet, ['read', 'submit', 'admit'])]
  const preSameEpoch = await craftBy(G, space, e1 + 1, hostile) // G pre-signs for the next epoch…
  const preFutureEpoch = await craftBy(G, space, e1 + 2, hostile) // …and, anticipating a revoke, for a FUTURE epoch

  // POSITIVE control — on a parallel space where G STILL holds admit, the SAME shape of record IS a legal successor.
  // So the refusals below are caused by the revocation, not by a malformed record.
  const ctrl = 'sp-rev-presign-ctrl'; const cm = await found(ctrl, [[G, ['read', 'submit', 'admit']]])
  assert.equal((await put(ctrl, await craftBy(G, ctrl, cm.epoch + 1, [...cm.members, pubMember(puppet, ['read', 'submit', 'admit'])]))).status, 200, 'while G holds admit its update is accepted')

  m = await revoke(m, A, G.id) // A revokes G → epoch e1+1, [A]; G is no longer an admit-holder in the current head
  assert.equal((await put(space, m)).status, 200)

  let r = await put(space, preSameEpoch)
  assert.equal(r.status, 403); assert.equal(r.body.error, 'unauthorized_update', 'the same-epoch pre-signed record loses the monotonic check')
  r = await put(space, preFutureEpoch)
  assert.equal(r.status, 403); assert.equal(r.body.error, 'unauthorized_update', 'the future-epoch record is refused — G holds no admit in the CURRENT head, whatever it signed earlier')
})

test('no-lockout: an admit-holder may remove another member, but not the last admit-holder', async () => {
  const space = 'sp-rev-lockout'
  const m = await found(space, [[G, ['read', 'submit', 'admit']], [O, ['read']]]) // A, G(admit), O
  // ALLOWED: A removes G while A remains an admit-holder
  assert.equal((await put(space, await craftBy(A, space, m.epoch + 1, m.members.filter((x) => x.party !== G.id)))).status, 200, 'removing a member while an admit remains is allowed')
  const cur = (await members(space)).body // now [A, O]
  // FORBIDDEN: strip the last admit (A demotes itself, nobody else holds admit) → the space would be un-governable
  const r = await put(space, await craftBy(A, space, cur.epoch + 1, cur.members.map((x) => (x.party === A.id ? { ...x, caps: ['read', 'submit'] } : x))))
  assert.equal(r.status, 403); assert.equal(r.body.error, 'unauthorized_update', 'removing the last admit-holder is refused (no-lockout)')
})

test('monotonic: even a current admit-holder cannot roll the epoch back or restamp an old record', async () => {
  const space = 'sp-rev-mono'
  const m = await found(space, [[G, ['read', 'submit']]]) // epoch 1
  for (const ep of [m.epoch, m.epoch - 1, 0]) { // same epoch, one back, and genesis — all ≤ current
    const r = await put(space, await craftBy(A, space, ep, m.members))
    assert.equal(r.status, 403, `epoch ${ep} refused`); assert.equal(r.body.error, 'unauthorized_update')
  }
  assert.equal((await put(space, await craftBy(A, space, m.epoch + 1, m.members))).status, 200, 'a strictly-greater epoch IS accepted (positive control)')
})

test('no fork: a second, different record at the same next epoch cannot split the chain', async () => {
  const space = 'sp-rev-fork'
  const m = await found(space, [[G, ['read', 'submit']]]) // epoch 1
  const branchA = await craftBy(A, space, m.epoch + 1, m.members.map((x) => (x.party === G.id ? { ...x, caps: ['read'] } : x)))
  const branchB = await craftBy(A, space, m.epoch + 1, m.members.map((x) => (x.party === G.id ? { ...x, caps: ['read', 'submit', 'admit'] } : x)))
  assert.equal((await put(space, branchA)).status, 200, 'the first record at e+1 is applied')
  const r = await put(space, branchB)
  assert.equal(r.status, 403); assert.equal(r.body.error, 'unauthorized_update', 'a competing record at the same epoch is refused — no fork on an honest server')
})
