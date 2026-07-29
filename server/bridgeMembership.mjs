// server/bridgeMembership.mjs — the Bridge Protocol's governance core (the Bridge protocol): KEY EPOCHS +
// MEMBERSHIP + CAPABILITIES. A shared Space is a sequence of epochs; each epoch has its own key `sharedMk_e`, sealed
// per-member to that member's public key (recipient-key model, reuses envelope.sealTo). Every membership change — a
// JOIN/ADMIT or a REVOKE — is an epoch boundary that mints a fresh key sealed to the NEW member set:
//   · revocation ⇒ real forward-secrecy (the removed party is not sealed the new key, so it reads no future content);
//   · a joiner gets NO back-history by default (invited into a conversation, not handed the transcript) — the admitter
//     MAY explicitly grant past epochs (history:'full'), which it can do because it already holds those keys.
// These are PARTY-side operations (a party mints the epoch key and re-seals it — the platform never holds a key, only
// the public membership record + the sealed grants = ciphertext). Capabilities {read,submit,admit,revoke} gate who may
// do what. Pure + immutable: every op returns a NEW membership record.
import { newRoomKey, sealTo, openBox, genRecipientKey } from './envelope.mjs'
import { signMembership } from './bridgeLog.mjs'

const ALL_CAPS = ['read', 'submit', 'admit', 'revoke']
const enc = new TextEncoder()

/** A stable party id from a public key jwk (canonicalized) — the fingerprint that attributes everything a party does. */
async function fingerprint(pubJwk) {
  const canon = JSON.stringify({ crv: pubJwk.crv, kty: pubJwk.kty, x: pubJwk.x, y: pubJwk.y })
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(canon)))
  return 'pty_' + [...h.slice(0, 12)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** Mint a party identity: a BOX keypair (ECDH — receives sealed epoch keys) + a SIGN keypair (ECDSA — attribution, used
 *  by the entry layer). The party id is the fingerprint of the SIGN key (the true identity). Holds the private keys;
 *  only the public halves go into the membership record. */
export async function genPartyIdentity() {
  const box = await genRecipientKey() // { publicJwk, privateJwk }, EC P-256 for ECDH sealing
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const sign = { pub: await crypto.subtle.exportKey('jwk', kp.publicKey), priv: await crypto.subtle.exportKey('jwk', kp.privateKey) }
  return { id: await fingerprint(sign.pub), box: { pub: box.publicJwk, priv: box.privateJwk }, sign }
}

/** The PUBLIC identity a party hands over to be admitted (what lands in the membership record — no private keys). */
export const publicIdentity = (idn) => ({ party: idn.id, boxPub: idn.box.pub, signPub: idn.sign.pub })

const memberOf = (m, partyId) => m.members.find((x) => x.party === partyId)
/** The capabilities of a party in this space (empty if not a member). */
export const capsOf = (m, partyId) => (memberOf(m, partyId)?.caps || [])
const requireCap = (m, actorId, cap) => { if (!capsOf(m, actorId).includes(cap)) throw new Error(`bridge: caller lacks '${cap}' cap`) }

/** Found a shared Space: the founder is the first member (full caps by default) at epoch 0. Mints sharedMk_0 sealed to
 *  the founder. PARTY-side (the founder holds the key; the returned record carries only the sealed grant). */
export async function openSpace(space, founder, { caps = ALL_CAPS, historyPolicy = 'none' } = {}) {
  const k0 = newRoomKey()
  const rec = {
    space,
    epoch: 0,
    admissionPolicy: 'cap', // whoever holds the `admit` cap may admit; other policies (all-consent) are a later refinement
    historyPolicy, // 'none' (default) → a joiner gets the current epoch only
    members: [{
      party: founder.id, boxPub: founder.box.pub, signPub: founder.sign.pub, caps,
      admittedBy: founder.id, admittedAt: 0, keyGrants: { 0: await sealTo(k0, founder.box.pub) },
    }],
  }
  rec.auth = { party: founder.id, sig: await signMembership(founder.sign.priv, rec) } // the founder SIGNS the genesis record → server-verifiable create
  return rec
}

/** The epoch key a party can open for `epoch`, or null when it holds no grant (⇒ no access to that epoch). */
export async function epochKey(membership, identity, epoch) {
  const m = memberOf(membership, identity.id)
  const grant = m && m.keyGrants[epoch]
  return grant ? openBox(grant, identity.box.priv) : null
}
/** The current epoch's key for a party (what it seals new entries under / reads current content with). */
export const currentKey = (membership, identity) => epochKey(membership, identity, membership.epoch)

/** ADMIT a new party (needs the `admit` cap). Opens a NEW epoch, mints its key, and seals it to EVERY member incl. the
 *  invitee. history:'full' additionally seals every past epoch key to the invitee — which the admitter can do because it
 *  already holds them. Returns the new membership record. */
export async function admit(membership, actor, invitee, { caps = ['read', 'submit'], history = 'none' } = {}) {
  requireCap(membership, actor.id, 'admit')
  if (memberOf(membership, invitee.party)) throw new Error('bridge: already a member')
  const e = membership.epoch + 1
  const k = newRoomKey() // the new epoch's key
  const inviteeMember = { party: invitee.party, boxPub: invitee.boxPub, signPub: invitee.signPub, caps, admittedBy: actor.id, admittedAt: e, keyGrants: {} }
  // seal the new epoch key to every member (existing + invitee)
  const members = await Promise.all([...membership.members, inviteeMember].map(async (m) => ({
    ...m, keyGrants: { ...m.keyGrants, [e]: await sealTo(k, m.boxPub) },
  })))
  // optional back-history: the admitter re-seals each past epoch key it holds to the invitee
  if (history === 'full') {
    const inv = members.find((m) => m.party === invitee.party)
    for (let pe = 0; pe < e; pe++) {
      const pk = await epochKey(membership, actor, pe)
      if (pk) inv.keyGrants[pe] = await sealTo(pk, invitee.boxPub)
    }
  }
  const next = { ...membership, epoch: e, members }
  next.auth = { party: actor.id, sig: await signMembership(actor.sign.priv, next) } // the admitter SIGNS the new record → server-verifiable
  return next
}

/** REVOKE a party (needs the `revoke` cap). Opens a new epoch sealed only to the REMAINING members → the removed party
 *  reads no future content (it keeps whatever past epochs it already held). Returns the new membership record. */
export async function revoke(membership, actor, partyId) {
  requireCap(membership, actor.id, 'revoke')
  if (!memberOf(membership, partyId)) throw new Error('bridge: not a member')
  if (partyId === actor.id) throw new Error('bridge: cannot revoke self')
  const e = membership.epoch + 1
  const k = newRoomKey()
  const members = await Promise.all(
    membership.members.filter((m) => m.party !== partyId).map(async (m) => ({ ...m, keyGrants: { ...m.keyGrants, [e]: await sealTo(k, m.boxPub) } })),
  )
  const next = { ...membership, epoch: e, members }
  next.auth = { party: actor.id, sig: await signMembership(actor.sign.priv, next) } // the revoker SIGNS the new record → server-verifiable
  return next
}

/** RE-CAP an existing member (needs `admit`) at a NEW epoch WITHOUT ejecting them: mint a fresh key sealed to EVERY
 *  current member (incl. the target — who KEEPS their key + read), only the target's caps change. A DOWNGRADE
 *  (submit→read) leaves a still-present read-only member — distinct from `revoke`, which removes them entirely. */
export async function recap(membership, actor, partyId, caps) {
  requireCap(membership, actor.id, 'admit')
  if (!memberOf(membership, partyId)) throw new Error('bridge: not a member')
  const e = membership.epoch + 1
  const k = newRoomKey()
  const members = await Promise.all(membership.members.map(async (m) => ({ ...m, caps: m.party === partyId ? caps : m.caps, keyGrants: { ...m.keyGrants, [e]: await sealTo(k, m.boxPub) } })))
  const next = { ...membership, epoch: e, members }
  next.auth = { party: actor.id, sig: await signMembership(actor.sign.priv, next) }
  return next
}
