import { test } from 'node:test'
import assert from 'node:assert/strict'
import { genPartyIdentity, publicIdentity, openSpace, admit } from './bridgeMembership.mjs'
import { genServerKey, makeEntry, makeCoSignedEntry, verifyAttribution, submit, verifyChain, checkpoint, verifyCheckpoint, chainMatchesCheckpoint, signMembership, verifyMembershipUpdate } from './bridgeLog.mjs'

const A = await genPartyIdentity() // founder — full caps
const B = await genPartyIdentity() // read + submit
const O = await genPartyIdentity() // observer — read only
const stranger = await genPartyIdentity() // never admitted
const server = await genServerKey()

let m = await openSpace('sp-shared-log', A)
m = await admit(m, A, publicIdentity(B)) // epoch 1
m = await admit(m, A, publicIdentity(O), { caps: ['read'] }) // epoch 2, O is read-only
const EP = m.epoch // 2 — entries must be sealed under the current epoch

async function buildLog(rows) {
  let log = [], now = 0
  for (const { id, body } of rows) {
    const r = await submit(log, m, await makeEntry(id, { space: m.space, epoch: EP, body }), { now: ++now })
    assert.ok(r.ok, r.error)
    log = r.log
  }
  return log
}

// ── co-signed crossings: a read-only assistant drafts, the human approves (the Asymmetric Bridge demo) ──────────────
test('co-signed crossing: the read-only assistant (O) drafts, the submitter (B) approves — both sigs verify + it crosses', async () => {
  const e = await makeCoSignedEntry(B, O, { space: m.space, actor: 'agent', epoch: EP, body: 'sealed-offer-1' })
  assert.equal(e.party, B.id, 'attributed to — and submitted by — the approver')
  assert.equal(e.draft.party, O.id, 'drafted by the read-only assistant')
  assert.equal(await verifyAttribution(m, e), true, 'BOTH signatures verify against the public membership')
  const r = await submit([], m, e, { now: 1 })
  assert.ok(r.ok, r.error) // the approver holds `submit`, so it crosses; the audit carries both keys
})

test('the read-only assistant can never cross anything alone — it is never the entry party (no_submit_cap)', async () => {
  assert.equal((await submit([], m, await makeEntry(O, { space: m.space, epoch: EP, body: 'sneak' }))).error, 'no_submit_cap')
})

test('a forged or non-member draft co-signature is rejected (verify + submit)', async () => {
  const e = await makeCoSignedEntry(B, O, { space: m.space, epoch: EP, body: 'sealed-offer-2' })
  assert.equal(await verifyAttribution(m, { ...e, draft: { party: O.id, sig: 'AAAA' } }), false, 'a bad draft sig fails')
  assert.equal(await verifyAttribution(m, { ...e, draft: { party: stranger.id, sig: e.draft.sig } }), false, 'a non-member drafter fails')
  assert.equal((await submit([], m, { ...e, draft: { party: O.id, sig: 'AAAA' } })).error, 'bad_signature', 'submit rejects it')
})

test('submit binds the space + epoch and rejects a replay (re-appended signed entry)', async () => {
  const e = await makeEntry(A, { space: m.space, epoch: EP, body: 'x1' })
  const r = await submit([], m, e, { now: 1 }); assert.ok(r.ok, r.error)
  assert.equal((await submit(r.log, m, e, { now: 2 })).error, 'replay', 'the same signed entry cannot be re-appended')
  // an entry signed FOR this space is refused when submitted against a different space (no cross-space replay)
  assert.equal((await submit([], { ...m, space: 'sp-OTHER' }, await makeEntry(A, { space: m.space, epoch: EP, body: 'y' }))).error, 'wrong_space')
})

test('a signed entry verifies; a tampered body fails; a non-member is not attributed', async () => {
  const e = await makeEntry(A, { space: m.space, kind: 'post', actor: 'human', epoch: EP, body: 'sealed-blob-1' })
  assert.equal(await verifyAttribution(m, e), true)
  assert.equal(await verifyAttribution(m, { ...e, body: 'sealed-blob-EVIL' }), false, 'changing the body breaks the signature')
  assert.equal(await verifyAttribution(m, await makeEntry(stranger, { space: m.space, epoch: EP, body: 'x' })), false)
})

test('submit enforces member + submit cap + current epoch + valid signature', async () => {
  let log = []
  let r = await submit(log, m, await makeEntry(A, { space: m.space, epoch: EP, body: 'a1' }), { now: 1 })
  assert.equal(r.ok, true); assert.equal(r.seq, 0); log = r.log
  r = await submit(log, m, await makeEntry(B, { space: m.space, epoch: EP, body: 'b1' }), { now: 2 })
  assert.equal(r.ok, true); assert.equal(r.seq, 1); log = r.log
  assert.equal((await submit(log, m, await makeEntry(O, { space: m.space, epoch: EP, body: 'o1' }))).error, 'no_submit_cap')
  assert.equal((await submit(log, m, await makeEntry(stranger, { space: m.space, epoch: EP, body: 's' }))).error, 'not_a_member')
  assert.equal((await submit(log, m, await makeEntry(A, { space: m.space, epoch: EP - 1, body: 'old' }))).error, 'wrong_epoch')
  const good = await makeEntry(A, { space: m.space, epoch: EP, body: 'a2' })
  assert.equal((await submit(log, m, { ...good, body: 'a2-EVIL' })).error, 'bad_signature')
})

test('the log is hash-chained; tampering a past entry breaks it', async () => {
  const log = await buildLog([{ id: A, body: 'a1' }, { id: B, body: 'b1' }, { id: A, body: 'a2' }])
  assert.equal(await verifyChain(log), true)
  const tampered = log.map((e, i) => (i === 0 ? { ...e, body: 'a1-EVIL' } : e))
  assert.equal(await verifyChain(tampered), false)
})

test('checkpoint: parties pin it; a server rewrite is detected against the pinned head', async () => {
  const log = await buildLog([{ id: A, body: 'a1' }, { id: B, body: 'b1' }])
  const cp = await checkpoint(server, log, { space: m.space, epoch: EP, now: 100 })
  assert.equal(await verifyCheckpoint(server.pub, cp), true)
  assert.equal(await chainMatchesCheckpoint(log, cp), true)
  assert.equal(await verifyCheckpoint((await genServerKey()).pub, cp), false, 'a forged checkpoint (wrong server key) fails')
  assert.equal(await chainMatchesCheckpoint(log.slice(0, -1), cp), false, 'a server that dropped an entry after pinning is caught')
})

// ── membership authorization — the server must refuse an update that upgrades a read-only party, adds an outsider, or
// rolls the epoch back. Only a signature from a CURRENT `admit`-holder over the new record is authoritative. ────────────
test('membership update: only a current admit-holder can authorize a new record', async () => {
  // craft a candidate next-record and sign it with an arbitrary party (the attacker or the legitimate admitter)
  const craft = async (signer, { epoch = m.epoch + 1, members = m.members } = {}) => {
    const next = { space: m.space, epoch, members }
    next.auth = { party: signer.id, sig: await signMembership(signer.sign.priv, next) }
    return next
  }
  // upgrade the read-only observer O to submit — the exact "upgrade the assistant" attack
  const upgradeO = m.members.map((x) => (x.party === O.id ? { ...x, caps: ['read', 'submit'] } : x))

  // POSITIVE control: A (holds admit) legitimately grants O submit → accepted
  assert.equal(await verifyMembershipUpdate(m, await craft(A, { members: upgradeO })), true, 'an admit-holder MAY re-cap a member')
  // and a plain admit result carries a valid auth
  assert.equal(await verifyMembershipUpdate(m, await admit(m, A, publicIdentity(stranger))), true, 'admit() is self-authorizing')

  // ATTACKS — every one must be refused:
  assert.equal(await verifyMembershipUpdate(m, await craft(O, { members: upgradeO })), false, 'O cannot upgrade itself (no admit cap)')
  assert.equal(await verifyMembershipUpdate(m, await craft(B, { members: upgradeO })), false, 'B has submit but not admit')
  assert.equal(await verifyMembershipUpdate(m, await craft(stranger, { members: upgradeO })), false, 'an outsider is not a member at all')
  // tamper: take a genuinely A-signed record, then swap the members after signing → signature no longer covers it
  const good = await craft(A)
  assert.equal(await verifyMembershipUpdate(m, { ...good, members: upgradeO }), false, 'body swapped after signing → sig fails')
  // epoch monotonicity: an authorized signature at the same or an earlier epoch is a rollback → refused
  assert.equal(await verifyMembershipUpdate(m, await craft(A, { epoch: m.epoch })), false, 'same epoch is not a successor')
  assert.equal(await verifyMembershipUpdate(m, await craft(A, { epoch: m.epoch - 1 })), false, 'earlier epoch is a rollback')
  // the un-signed PUT the old server accepted
  assert.equal(await verifyMembershipUpdate(m, { space: m.space, epoch: m.epoch + 1, members: upgradeO }), false, 'no auth → refused')
})
