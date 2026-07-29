// agent/bridgeSpace.mjs — the shared-Space SERVICE + the party client, composing the governance core
// ([[bridgeMembership]]: epochs/membership/caps) and the data plane ([[bridgeLog]]: signed, chained, checkpointed
// entries) into the Bridge Protocol (docs/bridge-protocol.md). The Lambda binding (native) and the signed-HTTPS binding
// (external) both call the SAME ops here. Content-blind: the service verifies signatures + caps + the chain and NEVER
// reads a body (sealed under the epoch key).
//
// The `party*` helpers are the CLIENT side — and they are identical for a native party (a witbitz comedian's Space) and
// an external party (someone else's agent + humans). That symmetry IS the interop: a party is an identity + the crypto,
// not witbitz machinery.
import { epochKey, currentKey } from './bridgeMembership.mjs'
import { submit as logSubmit, checkpoint as logCheckpoint, verifyAttribution, makeEntry } from './bridgeLog.mjs'
import { seal, open } from './envelope.mjs'

// ── SERVICE (server side — what a binding calls; immutable, returns new state) ────────────────────────────────────
/** A shared-space service instance holds { space, membership, log, serverKey }. */
export const createService = (space, membership, serverKey) => ({ space, membership, log: [], serverKey })
/** READ — entries since cursor (opaque sealed bodies) + the current epoch. A read teaches the server nothing. */
export const read = (svc, cursor = 0) => ({ entries: svc.log.slice(cursor), epoch: svc.membership.epoch })
/** MEMBERS — the public membership record (parties, pubkeys, caps, policies). */
export const members = (svc) => svc.membership
/** Apply a membership change produced party-side (an admit/revoke). (Signing the update so the service can verify the
 *  admitter's authority independently is a hardening — deferred; admit/revoke already require the cap client-side.) */
export const setMembership = (svc, membership) => ({ ...svc, membership })
/** SUBMIT — the log layer verifies member · `submit` cap · current epoch · signature, then chains it. */
export async function serviceSubmit(svc, entry, { now = 0 } = {}) {
  const r = await logSubmit(svc.log, svc.membership, entry, { now })
  return r.ok ? { ok: true, svc: { ...svc, log: r.log }, seq: r.seq } : { ok: false, error: r.error }
}
/** CHECKPOINT — the server signs the head for parties to pin + gossip. */
export const serviceCheckpoint = (svc, { now = 0 } = {}) => logCheckpoint(svc.serverKey, svc.log, { space: svc.space, epoch: svc.membership.epoch, now })

// ── PARTY (client side — native OR external, identical) ───────────────────────────────────────────────────────────
/** Build a signed, sealed entry (client-side) WITHOUT submitting — what a party POSTs over the HTTPS binding. Seals
 *  `content` under the current epoch key and signs it with the party key. */
export async function makePartyEntry(svc, identity, { content, kind = 'post', actor = 'agent' } = {}) {
  const key = await currentKey(svc.membership, identity)
  if (!key) throw new Error('party holds no current epoch key (not a member of this epoch)')
  const body = await seal(String(content), { mk: key }) // ciphertext — sealed under the shared epoch key
  return makeEntry(identity, { space: svc.space, kind, actor, epoch: svc.membership.epoch, body, clientHeadSeq: svc.log.length })
}
/** Seal `content`, sign it, and submit in one step. The platform never sees the plaintext. */
export async function partySubmit(svc, identity, { content, kind = 'post', actor = 'agent', now = 0 } = {}) {
  return serviceSubmit(svc, await makePartyEntry(svc, identity, { content, kind, actor }), { now })
}
/** Read the shared thread: for each entry, verify its attribution and decrypt its body with the epoch key this party
 *  holds (`content` is null for an epoch the party cannot open — e.g. pre-join history it was never granted). */
export async function partyRead(svc, identity, cursor = 0) {
  const out = []
  for (const e of svc.log.slice(cursor)) {
    const key = await epochKey(svc.membership, identity, e.epoch)
    out.push({ from: e.party, kind: e.kind, actor: e.actor, seq: e.seq, attributed: await verifyAttribution(svc.membership, e), content: key ? await open(e.body, { mk: key }) : null })
  }
  return out
}
