// server/bridge.equivocation.test.mjs — the EQUIVOCATING-server demo. Everything else proved the honest-server story:
// a server that FOLLOWS the rules can't accept a forged write. This is the dishonest-server story. A malicious operator
// can't forge entries (they're party-signed), but the party signature covers only the entry CORE, not the server's
// seq/at/prevHash — so it can REORDER/DROP the real signed entries, re-chain each fork, and sign a checkpoint for each.
// It then serves Emily one chain and Greg another. Each fork is internally consistent — chainMatchesCheckpoint passes
// for both — so NEITHER party can detect it alone. It is caught only when they COMPARE the checkpoints they pinned
// (gossip); and when caught, the operator is convicted by its OWN two signatures. This is the layer verify.md's
// conditional has flagged since round one.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { genPartyIdentity, publicIdentity, openSpace, admit } from './bridgeMembership.mjs'
import { genServerKey, makeEntry, submit, checkpoint, verifyCheckpoint, chainMatchesCheckpoint, checkpointConsistentWithLog, checkpointsConflict, verifyEquivocationProof } from './bridgeLog.mjs'

const emily = await genPartyIdentity() // founder
const assistant = await genPartyIdentity() // read-only
const greg = await genPartyIdentity() // read + submit
const server = await genServerKey()

let m = await openSpace('sp-equiv', emily)
m = await admit(m, emily, publicIdentity(assistant), { caps: ['read'] })
m = await admit(m, emily, publicIdentity(greg), { caps: ['read', 'submit'] })
const EP = m.epoch
const CP = (log, now = 100) => checkpoint(server, log, { space: m.space, epoch: EP, now })

// three REAL, party-signed crossings (bodies are opaque here; the point is the ORDER a server commits to)
const e1 = await makeEntry(emily, { space: m.space, epoch: EP, body: 'x1' })
const e2 = await makeEntry(greg, { space: m.space, epoch: EP, body: 'x2' })
const e3 = await makeEntry(emily, { space: m.space, epoch: EP, body: 'x3' })
// build a validly-chained log in a chosen ORDER — what a server (honest or not) does with the real signed entries.
async function buildLog(order) {
  let log = [], now = 0
  for (const e of order) { const r = await submit(log, m, e, { now: ++now }); assert.ok(r.ok, r.error); log = r.log }
  return log
}

test('honest server: two parties pin the SAME head → checkpoints agree, no equivocation', async () => {
  const L = await buildLog([e1, e2, e3])
  const cpEmily = await CP(L), cpGreg = await CP(L)
  assert.equal(await verifyCheckpoint(server.pub, cpEmily), true)
  assert.equal(checkpointsConflict(cpEmily, cpGreg), false, 'same head → no conflict')
  assert.equal(await checkpointConsistentWithLog(L, cpGreg), 'consistent')
  assert.equal(await verifyEquivocationProof(server.pub, cpEmily, cpGreg), false, 'no proof when they agree')
})

test('EQUIVOCATION: a server serving two internally-consistent forks is caught by comparing pinned checkpoints', async () => {
  const emilyLog = await buildLog([e1, e2, e3]) // the server shows Emily this order…
  const gregLog = await buildLog([e1, e3, e2]) // …and Greg a DIFFERENT order of the SAME real entries (re-chained)
  const cpEmily = await CP(emilyLog), cpGreg = await CP(gregLog)

  // 1) NEITHER party can detect it ALONE — each fork is a valid chain that matches its own server-signed checkpoint.
  assert.equal(await chainMatchesCheckpoint(emilyLog, cpEmily), true, "Emily's view is internally consistent")
  assert.equal(await chainMatchesCheckpoint(gregLog, cpGreg), true, "Greg's view is internally consistent")
  assert.equal(await verifyCheckpoint(server.pub, cpEmily), true)
  assert.equal(await verifyCheckpoint(server.pub, cpGreg), true)

  // 2) GOSSIP — they exchange the checkpoints they pinned. Each finds the other's head is NOT on its own chain.
  assert.equal(await checkpointConsistentWithLog(emilyLog, cpGreg), 'conflict', "Greg's pinned head is not on Emily's chain")
  assert.equal(await checkpointConsistentWithLog(gregLog, cpEmily), 'conflict', 'and vice-versa')

  // 3) PROOF — two server-signed checkpoints, one space+epoch, same seq, DIFFERENT head → the operator equivocated, and
  //    the proof is self-contained: anyone with the server's public key is convinced by the server's OWN two signatures.
  assert.equal(await verifyEquivocationProof(server.pub, cpEmily, cpGreg), true, 'the operator is convicted by its own signatures')
})

test('a party CANNOT frame an honest server: an equivocation proof needs two genuinely SERVER-signed checkpoints', async () => {
  const cpReal = await CP(await buildLog([e1, e2, e3]))
  const notTheServer = await genServerKey() // a party's own key, pretending to be the server
  const cpForged = await checkpoint(notTheServer, await buildLog([e1, e3, e2]), { space: m.space, epoch: EP, now: 100 })
  assert.equal(checkpointsConflict(cpReal, cpForged), true, 'the heads differ…')
  assert.equal(await verifyEquivocationProof(server.pub, cpReal, cpForged), false, "…but a forged checkpoint is not the server's → no proof (no framing)")
})

test('a party merely BEHIND is not falsely accused: a valid extension is "ahead", a shared prefix is "consistent"', async () => {
  const shortLog = await buildLog([e1, e2]) // seq 0..1
  const fullLog = await buildLog([e1, e2, e3]) // seq 0..2 — a valid EXTENSION of the same chain
  const cpFull = await CP(fullLog), cpShort = await CP(shortLog)
  assert.equal(await checkpointConsistentWithLog(shortLog, cpFull), 'ahead', "the full checkpoint is beyond my log — not a conflict")
  assert.equal(await checkpointConsistentWithLog(fullLog, cpShort), 'consistent', 'the shared prefix agrees')
  assert.equal(checkpointsConflict(cpFull, cpShort), false, 'different seqs → no false conflict')
})
