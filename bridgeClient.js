// bridgeClient.js — the browser (and Node) client for the Witbitz Bridge, for the Asymmetric Bridge demo.
//
// Keys never leave this file's runtime. The client:
//   · mints a party identity (an ECDSA SIGN key for attribution + an ECDH BOX key to receive epoch keys),
//   · founds / admits parties into a shared Bridge space (party-side re-key — the server never holds a key),
//   · seals each entry body under the current epoch key and SIGNS it, and — for a CO-SIGNED crossing — carries a
//     second signature so a reader can verify "authored by <assistant>, approved by <human>",
//   · reads the sealed thread and verifies every attribution against the PUBLIC membership record.
//
// The ONLY thing the server verifies is the signature over the canonical entry core (`canon` below, matched exactly to
// agent/bridgeLog.mjs). Epoch-key sealing and body encryption are party↔party — the platform stores opaque ciphertext.
// Isomorphic: uses only globals present in browsers and Node ≥20 (crypto.subtle, btoa/atob, fetch), so it is unit-
// tested in Node against the real agent/bridgeLog.mjs verifier and against the live API.

const subtle = crypto.subtle
const enc = new TextEncoder(), dec = new TextDecoder()

// ── base64url (isomorphic) ──────────────────────────────────────────────────────────────────────────────────────────
const b64u = (u8) => { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }
const ub64u = (str) => { const b = atob(String(str).replace(/-/g, '+').replace(/_/g, '/')); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u }

// ── canonical JSON — MUST byte-match agent/bridgeLog.mjs (both signer and verifier serialize identically) ────────────
function canon(o) {
  if (o === null || typeof o !== 'object') return JSON.stringify(o)
  if (Array.isArray(o)) return '[' + o.map(canon).join(',') + ']'
  return '{' + Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}'
}
async function sha256b64(str) { return b64u(new Uint8Array(await subtle.digest('SHA-256', enc.encode(str)))) }

// ── ECDSA P-256 attribution (matches the server's verify) ───────────────────────────────────────────────────────────
const importSignPriv = (jwk) => subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
const importSignPub = (jwk) => subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
async function signStr(privJwk, str) { return b64u(new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, await importSignPriv(privJwk), enc.encode(str)))) }
async function verifyStr(pubJwk, sigB64, str) { try { return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, await importSignPub(pubJwk), ub64u(sigB64), enc.encode(str)) } catch { return false } }

// ── ECDH box (seal a key to a party's box public key) + AES-GCM body sealing (party↔party; the server never opens) ────
const importEcdhPriv = (jwk) => subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey'])
const importEcdhPub = (jwk) => subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
async function ecdhKey(privJwk, pubJwk) { return subtle.deriveKey({ name: 'ECDH', public: await importEcdhPub(pubJwk) }, await importEcdhPriv(privJwk), { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']) }
async function aesGcm(key, u8) { const iv = crypto.getRandomValues(new Uint8Array(12)); const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, u8)); return { iv: b64u(iv), ct: b64u(ct) } }
async function aesOpen(key, o) { return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: ub64u(o.iv) }, key, ub64u(o.ct))) }

/** Seal a raw key (Uint8Array) to a recipient's box public key: ephemeral ECDH → AES-GCM. */
async function sealTo(rawKey, recipientBoxPub) {
  const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey'])
  const k = await ecdhKey(await subtle.exportKey('jwk', eph.privateKey), recipientBoxPub)
  return { eph: await subtle.exportKey('jwk', eph.publicKey), ...(await aesGcm(k, rawKey)) }
}
/** Open a sealed key with my box private key. */
async function openBox(sealed, myBoxPriv) { return aesOpen(await ecdhKey(myBoxPriv, sealed.eph), sealed) }

async function importEpochAes(raw) { return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']) }
async function sealBody(epochRaw, content) { return aesGcm(await importEpochAes(epochRaw), enc.encode(JSON.stringify(content))) }
async function openBody(epochRaw, body) { return JSON.parse(dec.decode(await aesOpen(await importEpochAes(epochRaw), body))) }

// ── party identity ──────────────────────────────────────────────────────────────────────────────────────────────────
/** A party id is the fingerprint of its SIGN public key (the true identity). */
async function fingerprint(signPubJwk) { return sha256b64(canon(signPubJwk)) }
export async function mintIdentity(label = '') {
  const s = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const b = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey'])
  const sign = { pub: await subtle.exportKey('jwk', s.publicKey), priv: await subtle.exportKey('jwk', s.privateKey) }
  const box = { pub: await subtle.exportKey('jwk', b.publicKey), priv: await subtle.exportKey('jwk', b.privateKey) }
  return { id: await fingerprint(sign.pub), label, sign, box }
}
export const publicIdentity = (idn) => ({ party: idn.id, label: idn.label || '', signPub: idn.sign.pub, boxPub: idn.box.pub })

// ── membership (party-side; the server just stores + serves it as the PUBLIC record) ────────────────────────────────
const ALL_CAPS = ['read', 'submit', 'admit', 'revoke']
const randKey = () => crypto.getRandomValues(new Uint8Array(32))

/** Found a shared space: the founder is the first member, epoch 0, key sealed to the founder's box. */
export async function openSpace(space, founder, { caps = ALL_CAPS } = {}) {
  const k0 = randKey()
  return { space, epoch: 0, members: [{ ...publicIdentity(founder), caps, keyGrants: { 0: await sealTo(k0, founder.box.pub) } }] }
}
/** Admit a party at a NEW epoch: mint a fresh key, seal it to EVERY member (incl. the invitee); no back-history. */
export async function admit(membership, actor, invitee, { caps = ['read', 'submit'] } = {}) {
  const e = membership.epoch + 1
  const ke = randKey()
  const members = await Promise.all(membership.members.map(async (m) => ({ ...m, keyGrants: { ...m.keyGrants, [e]: await sealTo(ke, m.boxPub) } })))
  members.push({ ...invitee, caps, keyGrants: { [e]: await sealTo(ke, invitee.boxPub) } })
  return { ...membership, epoch: e, members }
}
/** The current epoch key as raw bytes, opened with my box private key (null if I hold no grant). */
export async function epochKeyRaw(membership, identity) {
  const m = membership.members.find((x) => x.party === identity.id)
  const grant = m && m.keyGrants && m.keyGrants[membership.epoch]
  return grant ? new Uint8Array(await openBox(grant, identity.box.priv)) : null
}

// ── entries ─────────────────────────────────────────────────────────────────────────────────────────────────────────
const entryCore = (e) => ({ space: e.space, party: e.party, kind: e.kind, actor: e.actor, epoch: e.epoch, body: e.body, clientHeadSeq: e.clientHeadSeq, nonce: e.nonce })

/** A single-party signed entry (a human posting directly). */
export async function makeEntry(membership, identity, { content, kind = 'post', actor = 'human', clientHeadSeq = 0 } = {}) {
  const epochRaw = await epochKeyRaw(membership, identity)
  const core = { space: membership.space, party: identity.id, kind, actor, epoch: membership.epoch, body: await sealBody(epochRaw, content), clientHeadSeq, nonce: b64u(crypto.getRandomValues(new Uint8Array(12))) }
  return { ...core, sig: await signStr(identity.sign.priv, canon(core)) }
}
/** A CO-SIGNED crossing: the read-only `drafter` signs the same core the `submitter` approves + signs. */
export async function makeCoSignedEntry(membership, submitter, drafter, { content, kind = 'post', clientHeadSeq = 0 } = {}) {
  const epochRaw = await epochKeyRaw(membership, submitter)
  const core = { space: membership.space, party: submitter.id, kind, actor: 'agent', epoch: membership.epoch, body: await sealBody(epochRaw, content), clientHeadSeq, nonce: b64u(crypto.getRandomValues(new Uint8Array(12))) }
  const c = canon(core)
  return { ...core, sig: await signStr(submitter.sign.priv, c), draft: { party: drafter.id, sig: await signStr(drafter.sign.priv, c) } }
}

/** Verify an entry's attribution against the public membership: the party's signature, and — if co-signed — the
 *  drafter's independent signature over the same core. Returns { ok, party, drafter } for `[check this]`. */
export async function verifyEntry(membership, entry) {
  const m = membership.members.find((x) => x.party === entry.party)
  if (!m || !entry.sig) return { ok: false }
  const core = canon(entryCore(entry))
  if (!(await verifyStr(m.signPub, entry.sig, core))) return { ok: false }
  let drafter = null
  if (entry.draft) {
    const d = membership.members.find((x) => x.party === entry.draft.party)
    if (!d || !entry.draft.sig || !(await verifyStr(d.signPub, entry.draft.sig, core))) return { ok: false }
    drafter = d
  }
  return { ok: true, party: m, drafter }
}

/** Open an entry body with the epoch key I hold (null content if I can't — "sealed to a key I don't hold"). */
export async function openEntry(membership, identity, entry) {
  const m = membership.members.find((x) => x.party === identity.id)
  const grant = m && m.keyGrants && m.keyGrants[entry.epoch]
  if (!grant) return null
  try { return await openBody(new Uint8Array(await openBox(grant, identity.box.priv)), entry.body) } catch { return null }
}

// ── HTTP binding (the Bridge REST API) ──────────────────────────────────────────────────────────────────────────────
export function bridge(base) {
  const j = async (r) => { const t = await r.text(); let d = {}; try { d = t ? JSON.parse(t) : {} } catch { /* */ } if (!r.ok) throw Object.assign(new Error(d.error || r.status), { status: r.status, data: d }); return d }
  return {
    create: (membership) => fetch(`${base}/spaces`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(membership) }).then(j),
    getMembers: (space) => fetch(`${base}/spaces/${encodeURIComponent(space)}/members`).then(j),
    putMembers: (space, membership) => fetch(`${base}/spaces/${encodeURIComponent(space)}/members`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(membership) }).then(j),
    submit: (space, entry) => fetch(`${base}/spaces/${encodeURIComponent(space)}/entries`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(entry) }).then(j),
    read: (space, cursor = 0) => fetch(`${base}/spaces/${encodeURIComponent(space)}/entries?cursor=${cursor}`).then(j),
  }
}

export { canon }
