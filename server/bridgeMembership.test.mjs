import { test } from 'node:test'
import assert from 'node:assert/strict'
import { genPartyIdentity, publicIdentity, openSpace, admit, revoke, epochKey, currentKey, capsOf } from './bridgeMembership.mjs'

// Three parties: A founds the shared space, B is admitted, C is a later join.
const A = await genPartyIdentity()
const B = await genPartyIdentity()
const C = await genPartyIdentity()

test('a party identity has a stable id (fingerprint of its sign key) + a box + a sign keypair', () => {
  assert.match(A.id, /^pty_[0-9a-f]{24}$/)
  assert.notEqual(A.id, B.id)
  assert.ok(A.box.pub && A.box.priv && A.sign.pub && A.sign.priv)
  assert.deepEqual(publicIdentity(A), { party: A.id, boxPub: A.box.pub, signPub: A.sign.pub }) // no private keys leak
})

test('openSpace: founder is a full-cap member at epoch 0 and can open sharedMk_0', async () => {
  const m = await openSpace('sp-shared-1', A)
  assert.equal(m.epoch, 0)
  assert.deepEqual(capsOf(m, A.id), ['read', 'submit', 'admit', 'revoke'])
  assert.ok(await currentKey(m, A), 'founder opens the epoch-0 key')
})

test('admit: new epoch, both members open the NEW key, the joiner gets NO back-history by default', async () => {
  let m = await openSpace('sp-shared-2', A)
  const k0_A = await epochKey(m, A, 0)
  m = await admit(m, A, publicIdentity(B)) // B: read+submit
  assert.equal(m.epoch, 1)
  assert.deepEqual(capsOf(m, B.id), ['read', 'submit'])
  // both open the current (epoch-1) key
  const k1_A = await currentKey(m, A)
  const k1_B = await currentKey(m, B)
  assert.ok(k1_A && k1_B && k1_A === k1_B, 'A and B share the epoch-1 key')
  // the founder still opens epoch 0; the joiner CANNOT (no history)
  assert.equal(await epochKey(m, A, 0), k0_A, 'A keeps epoch-0 access')
  assert.equal(await epochKey(m, B, 0), null, 'B has no epoch-0 grant → no back-history')
})

test('admit history:full: the joiner is explicitly granted the past epochs', async () => {
  let m = await openSpace('sp-shared-3', A)
  const k0 = await epochKey(m, A, 0)
  m = await admit(m, A, publicIdentity(B), { history: 'full' })
  assert.equal(await epochKey(m, B, 0), k0, "B was granted epoch 0 → sees the history the couple chose to share")
})

test('revoke: forward-secrecy — the removed party cannot open the new epoch (keeps only what it already held)', async () => {
  let m = await openSpace('sp-shared-4', A)
  m = await admit(m, A, publicIdentity(B)) // epoch 1: A + B
  const k1_B = await epochKey(m, B, 1) // B opens epoch 1 WHILE a member — it holds this key material from now on
  assert.ok(k1_B, 'B opened epoch 1 while present')
  m = await revoke(m, A, B.id) // epoch 2: A only. B is removed from the record.
  assert.equal(m.epoch, 2)
  assert.ok(await currentKey(m, A), 'A opens the post-revoke epoch')
  assert.equal(await epochKey(m, B, 2), null, 'B cannot open the epoch minted after its removal (forward secrecy)')
  // "can't un-see": B is gone from the record, but it already extracted k1_B above — that content stays readable to B
  // (a client-side truth, not a post-revoke record lookup). Revocation protects the FUTURE, not the past.
  assert.ok(k1_B)
})

test('capabilities gate who may admit/revoke', async () => {
  let m = await openSpace('sp-shared-5', A)
  m = await admit(m, A, publicIdentity(B)) // B has read+submit, NOT admit/revoke
  await assert.rejects(() => admit(m, B, publicIdentity(C)), /lacks 'admit'/, 'B cannot admit C')
  await assert.rejects(() => revoke(m, B, A.id), /lacks 'revoke'/, 'B cannot revoke A')
  // an admitter CAN — grant B admit+revoke by re-admitting fresh party D with those caps and letting D act
  const D = await genPartyIdentity()
  m = await admit(m, A, publicIdentity(D), { caps: ['read', 'submit', 'admit', 'revoke'] })
  const m2 = await admit(m, D, publicIdentity(C)) // D (has admit) can admit C
  assert.ok(capsOf(m2, C.id).length, 'D admitted C')
})

test('epochKey returns null for a non-member / a missing grant', async () => {
  const m = await openSpace('sp-shared-6', A)
  assert.equal(await epochKey(m, B, 0), null) // B was never admitted
})
