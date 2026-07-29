// server/bridge.gossip.test.mjs — the GOSSIP TRANSPORT: the cross-party exchange that turns the equivocation-detection
// primitives (bridge.equivocation.test) into an end-to-end guarantee. Two parties each PIN the checkpoint the server
// showed THEM, then hand it to the other OVER A SIDE CHANNEL INDEPENDENT OF THE AUDITED SERVER — routing the gossip
// through the Bridge would let a malicious server equivocate on the gossip too. Each auto-compares the peer's pinned
// head against its own log. The payoff, and the reason this closes the loop: on a fork the two checkpoints are a
// SELF-AUTHENTICATING proof — a THIRD PARTY who trusts NEITHER party is convinced with only the server's public key,
// because the server is convicted by its own two signatures. Neither party can fabricate the accusation.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { genPartyIdentity, publicIdentity, openSpace, admit } from './bridgeMembership.mjs'
import { genServerKey, makeEntry, submit, checkpoint, checkpointConsistentWithLog, checkpointsConflict, verifyEquivocationProof } from './bridgeLog.mjs'

const emily = await genPartyIdentity(), greg = await genPartyIdentity(), assistant = await genPartyIdentity()
const server = await genServerKey()
let m = await openSpace('sp-gossip', emily)
m = await admit(m, emily, publicIdentity(assistant), { caps: ['read'] })
m = await admit(m, emily, publicIdentity(greg), { caps: ['read', 'submit'] })
const EP = m.epoch
const CP = (log) => checkpoint(server, log, { space: m.space, epoch: EP, now: 100 })
const e1 = await makeEntry(emily, { space: m.space, epoch: EP, body: 'x1' })
const e2 = await makeEntry(greg, { space: m.space, epoch: EP, body: 'x2' })
const e3 = await makeEntry(emily, { space: m.space, epoch: EP, body: 'x3' })
async function buildLog(order) { let log = [], now = 0; for (const e of order) { const r = await submit(log, m, e, { now: ++now }); log = r.log } return log }

// The party-side gossip receiver — mirrored byte-for-byte by the browser client's `auditAgainstPeer`. It takes the
// peer's checkpoint as a DIRECT argument: the transport hands it over out-of-band; this never asks a server for it.
async function audit(myLog, myCp, peerCp) {
  const verdict = await checkpointConsistentWithLog(myLog, peerCp)
  const proof = verdict === 'conflict' && checkpointsConflict(myCp, peerCp) ? { space: peerCp.space, epoch: peerCp.epoch, cpA: myCp, cpB: peerCp } : null
  return { verdict, equivocation: verdict === 'conflict', proof }
}

test('honest server: the gossip exchange raises no alarm (both pinned the same head)', async () => {
  const L = await buildLog([e1, e2, e3])
  const cpEmily = await CP(L), cpGreg = await CP(L)
  // Emily receives Greg's pinned checkpoint out-of-band and audits it against her own view:
  assert.deepEqual(await audit(L, cpEmily, cpGreg), { verdict: 'consistent', equivocation: false, proof: null })
  assert.deepEqual(await audit(L, cpGreg, cpEmily), { verdict: 'consistent', equivocation: false, proof: null })
})

test('equivocating server: the gossip exchange AUTO-FLAGS the fork and yields a proof', async () => {
  const emilyLog = await buildLog([e1, e2, e3]) // the server showed Emily this order…
  const gregLog = await buildLog([e1, e3, e2]) // …and Greg a different order (re-chained) — each internally consistent
  const cpEmily = await CP(emilyLog), cpGreg = await CP(gregLog)

  const emilySees = await audit(emilyLog, cpEmily, cpGreg) // Emily receives Greg's checkpoint (side channel) → compares
  const gregSees = await audit(gregLog, cpGreg, cpEmily)
  assert.equal(emilySees.equivocation, true, "Greg's pinned head is not on Emily's chain → flagged")
  assert.equal(gregSees.equivocation, true, 'and symmetrically for Greg')
  assert.ok(emilySees.proof && emilySees.proof.cpA && emilySees.proof.cpB, 'a proof (two conflicting checkpoints) is produced')
})

test('THIRD PARTY: the proof convicts the operator by ITS OWN signatures — trusting neither party, no logs, just serverPub', async () => {
  const emilyLog = await buildLog([e1, e2, e3]), gregLog = await buildLog([e1, e3, e2])
  const { proof } = await audit(emilyLog, await CP(emilyLog), await CP(gregLog))
  assert.ok(proof, 'Emily produced a proof')
  // A neutral verifier holds ONLY the server's checkpoint public key + the proof — not Emily's or Greg's logs or keys.
  assert.equal(await verifyEquivocationProof(server.pub, proof.cpA, proof.cpB), true, 'the server equivocated — proven to anyone')
  // …and the accusation is UNFORGEABLE: a party can't frame an honest server with a checkpoint it signed itself.
  const impostor = await genServerKey()
  const fake = { ...proof.cpB, sig: (await checkpoint(impostor, gregLog, { space: m.space, epoch: EP, now: 100 })).sig }
  assert.equal(await verifyEquivocationProof(server.pub, proof.cpA, fake), false, 'a forged half is not the server’s → no conviction')
})
