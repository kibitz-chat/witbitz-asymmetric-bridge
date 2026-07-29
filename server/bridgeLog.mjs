// agent/bridgeLog.mjs — the Bridge Protocol's data plane (docs/bridge-protocol.md): SIGNED, epoch-tagged entries, a
// hash-chained append-only log, and a server-signed CHECKPOINT. This is what makes the audit trustless:
//   · ATTRIBUTION — the CLIENT signs each entry with its party key (ECDSA); the platform verifies against the public
//     membership record, ON CIPHERTEXT (it never reads `body`). No party can speak as another.
//   · INTEGRITY — the SERVER assigns order (seq) and chains entries (prevHash), then signs a CHECKPOINT of the head.
//     Parties PIN checkpoints; a server that later reorders/drops entries can't match a checkpoint someone already
//     holds. (Gossip of checkpoints catches equivocation; the full public transparency log is M4.)
// The log layer is content-blind: `body` is an opaque sealed blob (sealed under the epoch key by bridgeMembership) —
// this module only signs, verifies, and chains it. Pure + immutable.
const enc = new TextEncoder()
const toB64 = (u8) => Buffer.from(u8).toString('base64url')
const fromB64 = (s) => Buffer.from(String(s), 'base64url')

// Canonical (stable-key-order) JSON — both signer and verifier MUST serialize identically.
function canon(o) {
  if (o === null || typeof o !== 'object') return JSON.stringify(o)
  if (Array.isArray(o)) return '[' + o.map(canon).join(',') + ']'
  return '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}'
}
async function sha256b64(str) { return toB64(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(str)))) }
const importPriv = (jwk) => crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
const importPub = (jwk) => crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
async function signStr(privJwk, str) { return toB64(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, await importPriv(privJwk), enc.encode(str)))) }
async function verifyStr(pubJwk, sigB64, str) { try { return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, await importPub(pubJwk), fromB64(sigB64), enc.encode(str)) } catch { return false } }

/** A server/checkpoint keypair — the Lambda holds it to sign the audit head. */
export async function genServerKey() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return { pub: await crypto.subtle.exportKey('jwk', kp.publicKey), priv: await crypto.subtle.exportKey('jwk', kp.privateKey) }
}

// The client-signed core of an entry (everything except the server-assigned seq/at/prevHash).
const entryCore = (e) => ({ space: e.space, party: e.party, kind: e.kind, actor: e.actor, epoch: e.epoch, body: e.body, clientHeadSeq: e.clientHeadSeq, nonce: e.nonce })

/** CLIENT: sign an entry with the party's key. `body` is already-sealed ciphertext (opaque here). */
export async function makeEntry(identity, { space, kind = 'post', actor = 'agent', epoch, body, clientHeadSeq = 0 } = {}) {
  const nonce = toB64(crypto.getRandomValues(new Uint8Array(12)))
  const core = { space, party: identity.id, kind, actor, epoch, body, clientHeadSeq, nonce }
  return { ...core, sig: await signStr(identity.sign.priv, canon(core)) }
}

/** CLIENT: a CO-SIGNED crossing. The DRAFTER (e.g. a read-only assistant) signs the same core the SUBMITTER approves and
 *  signs. The entry is attributed to — and submitted by — the submitter; `draft` carries the drafter's independent
 *  signature over the identical core, so a reader verifies BOTH ("authored by X, approved by Y") against the public
 *  membership. The drafter needs no `submit` cap: it is never the entry's `party`, so it can never cross anything alone. */
export async function makeCoSignedEntry(submitter, drafter, { space, kind = 'post', actor = 'agent', epoch, body, clientHeadSeq = 0 } = {}) {
  const nonce = toB64(crypto.getRandomValues(new Uint8Array(12)))
  const core = { space, party: submitter.id, kind, actor, epoch, body, clientHeadSeq, nonce }
  const c = canon(core)
  return { ...core, sig: await signStr(submitter.sign.priv, c), draft: { party: drafter.id, sig: await signStr(drafter.sign.priv, c) } }
}

/** Verify an entry's ATTRIBUTION: the party is a member and its signature over the core verifies against its signPub. */
export async function verifyAttribution(membership, entry) {
  const m = membership.members.find((x) => x.party === entry.party)
  if (!m || !entry.sig) return false
  const core = canon(entryCore(entry))
  if (!(await verifyStr(m.signPub, entry.sig, core))) return false
  if (entry.draft) { // a CO-SIGNED crossing (a read-only assistant drafted, the submitter approved): the drafter must
    const d = membership.members.find((x) => x.party === entry.draft.party) // be a member, and its independent signature
    if (!d || !entry.draft.sig) return false                                // over the SAME core must verify too
    if (!(await verifyStr(d.signPub, entry.draft.sig, core))) return false
  }
  return true
}

// ── membership authority (admit/revoke) — the SERVER verifies the update independently, so no one can PUT a membership
// that upgrades a read-only party, adds themselves, or rolls the epoch back. The authorizer must hold `admit` in the
// CURRENT record and sign the NEW one. Signed content is {space, epoch, members} (caps + grants) — never `auth` itself.
export const membershipCore = (m) => canon({ space: m.space, epoch: m.epoch, members: m.members })
/** CLIENT: an admit/revoke-capable actor signs the new membership record. */
export async function signMembership(actorSignPriv, membership) { return signStr(actorSignPriv, membershipCore(membership)) }
/** SERVER: is `next` a LEGAL SUCCESSOR of the current head `cur`? This is a DELIBERATE policy (docs/bridge-protocol.md
 *  §membership-succession), not merely "internally consistent + signed":
 *   · same space, strictly-advancing epoch — monotonic, so an OLDER record can't be replayed;
 *   · signed by a party holding `admit` IN `cur` — authority is re-checked at APPLY time against the CURRENT head, never
 *     "in some record." So a party whose admit was revoked cannot apply a record it pre-signed while it still held admit
 *     (the classic pre-signed-transition attack): by the time it submits, it is no longer an admit-holder in `cur`. The
 *     signature is necessary, never sufficient;
 *   · ≥1 admit-holder remains — NO-LOCKOUT. An admit-holder MAY re-cap or remove ANY member (incl. the founder) — that is
 *     what `admit` grants, and in practice it is held only by a trusted party — but may not brick the space.
 *  NOT enforced, by deliberate choice: key-completeness of `next` (a member denied the new epoch key simply can't
 *  decrypt — self-evident to it) and `prev`-hash chaining of the membership sequence (equivocation is the checkpoint
 *  layer's job, not membership linkage). */
export async function verifyMembershipUpdate(cur, next) {
  if (!cur || !next || !next.auth) return false
  if (next.space !== cur.space || !Array.isArray(next.members) || !(next.epoch > cur.epoch)) return false
  if (!next.members.some((x) => Array.isArray(x.caps) && x.caps.includes('admit'))) return false // no-lockout: never zero admits
  const actor = cur.members.find((x) => x.party === next.auth.party) // authority = the CURRENT head, re-checked at apply time
  if (!actor || !actor.caps.includes('admit')) return false
  return verifyStr(actor.signPub, next.auth.sig, membershipCore(next))
}

/** SERVER: is this a legitimately-founded GENESIS record? `create` is the one write that has no predecessor to check
 *  against, so it must at least be SIGNED by the founder it names: epoch 0 · ≥1 admit-holder · signed by an admit-holder.
 *  So no one can found a space in ANOTHER party's name (the named founder's key must sign). It does NOT by itself stop
 *  id-squatting — whoever creates an unclaimed id FIRST owns it (409 on re-create). The product must therefore mint the
 *  space id AT create as a commitment to the founder, never pre-share it (docs/bridge-protocol.md §Founding). */
export async function verifyCreate(membership) {
  if (!membership || !membership.auth || !Array.isArray(membership.members) || membership.epoch !== 0) return false
  if (!membership.members.some((x) => Array.isArray(x.caps) && x.caps.includes('admit'))) return false
  const actor = membership.members.find((x) => x.party === membership.auth.party)
  if (!actor || !actor.caps.includes('admit')) return false
  return verifyStr(actor.signPub, membership.auth.sig, membershipCore(membership))
}

// Teardown (DELETE) is authenticated: a CURRENT `admit`-holder signs a delete assertion bound to the space id + a fresh
// TIMESTAMP. This is a TIME-BOUND signed authorization — a captured token EXPIRES (maxSkewMs) rather than working
// forever; it is honestly NOT single-use (true single-use would require the server to remember spent tokens, which is
// pointless for a one-shot operation that removes its own target — after a successful delete there is nothing left to
// replay against → 204 idempotent). It rides in a REQUEST HEADER (`x-bridge-authorization`), sturdier than a DELETE
// body which some proxies/CDNs strip, and out of the URL so it isn't left in access logs. (The route additionally
// restricts DELETE to the disposable sp-ci-* namespace, so even an authorized signature can't remove a real space.)
const deleteCore = (space, ts) => canon({ op: 'delete', space, ts })
/** CLIENT: an admit-capable actor authorizes tearing a space down, bound to this moment (ts). */
export async function signDelete(actorSignPriv, space, ts) { return signStr(actorSignPriv, deleteCore(space, ts)) }
/** SERVER: does `auth` = { party, sig, ts } authorize deleting this membership's space? member · holds `admit` · ts is
 *  FRESH (bounded — a leaked authorization can't be replayed after the window) · sig binds space+ts. */
export async function verifyDelete(membership, auth, { now = 0, maxSkewMs = 600000 } = {}) {
  if (!membership || !auth || !auth.party || !auth.sig || typeof auth.ts !== 'number') return false
  if (!(Math.abs(now - auth.ts) <= maxSkewMs)) return false // freshness window — not a permanent capability
  const actor = membership.members.find((x) => x.party === auth.party)
  if (!actor || !actor.caps.includes('admit')) return false
  return verifyStr(actor.signPub, auth.sig, deleteCore(membership.space, auth.ts))
}

// The stored form's hash (what the chain links + the checkpoint commits to) — includes the server fields.
const storedHash = (e) => sha256b64(canon({ ...entryCore(e), sig: e.sig, draft: e.draft || null, seq: e.seq, at: e.at, prevHash: e.prevHash }))

/** SERVER: accept an entry into the log. Checks member · has `submit` · epoch is current · signature valid; then
 *  assigns seq/at/prevHash and appends. Returns { ok, log, seq } or { ok:false, error } — WITHOUT reading `body`. */
export async function submit(log, membership, entry, { now = 0 } = {}) {
  const m = membership.members.find((x) => x.party === entry.party)
  if (!m) return { ok: false, error: 'not_a_member' }
  if (!m.caps.includes('submit')) return { ok: false, error: 'no_submit_cap' }
  if (entry.space !== membership.space) return { ok: false, error: 'wrong_space' } // the entry is SIGNED for a space — bind it, so a valid entry can't be replayed into another
  if (entry.epoch !== membership.epoch) return { ok: false, error: 'wrong_epoch' }
  if (!(await verifyAttribution(membership, entry))) return { ok: false, error: 'bad_signature' }
  if (log.some((x) => x.party === entry.party && x.nonce === entry.nonce)) return { ok: false, error: 'replay' } // the (party,nonce) is in the signed core → no re-append of the same signed entry
  const prev = log[log.length - 1]
  const stored = { ...entry, seq: log.length, at: now, prevHash: prev ? await storedHash(prev) : '' }
  return { ok: true, log: [...log, stored], seq: stored.seq }
}

/** Every entry's prevHash chains to the prior entry — tamper-evidence WITHIN the log (a changed/dropped entry breaks it). */
export async function verifyChain(log) {
  for (let i = 1; i < log.length; i++) if (log[i].prevHash !== (await storedHash(log[i - 1]))) return false
  return true
}

/** SERVER: sign a checkpoint over the current head — parties pin this. */
export async function checkpoint(serverKey, log, { space, epoch, now = 0 } = {}) {
  const core = { space, epoch, headSeq: log.length - 1, headHash: log.length ? await storedHash(log[log.length - 1]) : '', at: now }
  return { ...core, sig: await signStr(serverKey.priv, canon(core)) }
}
/** Verify a checkpoint is genuinely the server's. */
export async function verifyCheckpoint(serverPub, cp) { const { sig, ...core } = cp; return verifyStr(serverPub, sig, canon(core)) }
/** A pinned checkpoint vs a served log: does the log's head match what the checkpoint committed to? (Catches a server
 *  that rewrote history after the checkpoint was pinned.) */
export async function chainMatchesCheckpoint(log, cp) {
  const headHash = log.length ? await storedHash(log[log.length - 1]) : ''
  return headHash === cp.headHash && log.length - 1 === cp.headSeq
}

// ── GOSSIP — cross-party EQUIVOCATION detection ──────────────────────────────────────────────────────────────────────
// chainMatchesCheckpoint catches a server that rewrote history in MY OWN view. It does NOT catch EQUIVOCATION: a server
// serving two internally-consistent but DIFFERENT logs to two parties. The server can't forge entries (they're
// party-signed), but the party signature covers only the entry CORE — NOT the server-assigned seq/at/prevHash — so a
// malicious server can freely REORDER/DROP real entries, re-chain, and sign a checkpoint for each fork. Each fork passes
// its own chainMatchesCheckpoint; neither party can tell ALONE. It is caught only by COMPARING the checkpoints two
// parties pinned + gossip — and when it is, the server is convicted by its OWN signatures. These are the comparison.

/** Does a (server-signed) checkpoint agree with MY log at its head-seq? 'consistent' | 'conflict' (its head is NOT on my
 *  chain → equivocation) | 'ahead' (its head is beyond my log — I can't refute it yet). */
export async function checkpointConsistentWithLog(log, cp) {
  if (!cp) return 'conflict'
  if (cp.headSeq < 0) return log.length === 0 ? 'consistent' : 'conflict'
  if (cp.headSeq > log.length - 1) return 'ahead' // their head is past mine — no proof either way
  return (await storedHash(log[cp.headSeq])) === cp.headHash ? 'consistent' : 'conflict'
}

/** Two checkpoints for the SAME space+epoch at the SAME head-seq committing to DIFFERENT heads = a provable fork,
 *  LOG-FREE. (Different seqs are not decidable here — use checkpointConsistentWithLog against a log spanning both.) */
export function checkpointsConflict(cpA, cpB) {
  if (!cpA || !cpB || cpA.space !== cpB.space || cpA.epoch !== cpB.epoch) return false
  return cpA.headSeq === cpB.headSeq && cpA.headHash !== cpB.headHash
}

/** PROOF of equivocation: two checkpoints that CONFLICT and are BOTH genuinely the server's. Anyone holding the server's
 *  public key verifies it — the operator is convicted by its own two signatures over one space's two conflicting heads.
 *  A party CANNOT frame an honest server: a forged conflicting checkpoint isn't the server's, so verifyCheckpoint fails. */
export async function verifyEquivocationProof(serverPub, cpA, cpB) {
  if (!checkpointsConflict(cpA, cpB)) return false
  return (await verifyCheckpoint(serverPub, cpA)) && (await verifyCheckpoint(serverPub, cpB))
}
