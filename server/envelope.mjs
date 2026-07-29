// server/envelope.mjs — the crypto primitives the Bridge uses, and ONLY those. This is a deliberately STRIPPED copy of
// the platform envelope: it is SINGLE-RECIPIENT. There is no operator "beta" slot (a second symmetric recipient under an
// operator-held per-room key) and no "admin" RSA slot (an offline debug reader) — mechanisms that would let a record be
// sealed so the operator can read it. The Bridge never seals to anyone but the parties, so this demo, whose headline is
// "the operator is blind," ships no code that contradicts it. Two shapes:
//   · symmetric envelope — AES-256-GCM under HKDF(mk,"memwrap"); the ONLY recipient is `room` (the mk-holder). Used to
//     seal an entry body under the current epoch key.
//   · sealed box (public-key) — anonymous ephemeral ECDH-P256 → HKDF("sealedbox") → AES-256-GCM; seal to a recipient's
//     public key, open with their private key. Used to seal each epoch key to each member's box key (recipient model).
// Everything on the wire is ciphertext; `mk` and the box private keys are the only secrets. Wrong key → GCM auth fails
// → null (fail-closed). Pure crypto: Node ≥20 / browser `crypto.subtle` only, no other imports.
const crypto = globalThis.crypto
const enc = new TextEncoder()
const dec = new TextDecoder()
const VERSION = 1
const b64 = (b) => Buffer.from(b).toString('base64url')
const ub64 = (s) => new Uint8Array(Buffer.from(String(s || ''), 'base64url'))

// mk (base64url, 32 random bytes) → an AES-256-GCM wrap key via HKDF. Stable info string so reads match writes.
async function roomWrapKey(mk) {
  const ikm = await crypto.subtle.importKey('raw', ub64(mk), 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('memwrap') }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

/** A fresh random room/epoch key (base64url) — a party mints it and seals it to the member set. */
export function newRoomKey() {
  return b64(crypto.getRandomValues(new Uint8Array(32)))
}

// Wrap the content-encryption key (CEK) under the room key → { iv, w }.
async function wrapSym(key, cek) {
  const wk = await roomWrapKey(key)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const w = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wk, cek))
  return { iv: b64(iv), w: b64(w) }
}

/** Seal a string to the room key `mk` — the SOLE recipient. (No beta/admin slots: the operator is not a recipient.) */
export async function seal(plaintext, { mk } = {}) {
  if (!mk) throw new Error('seal needs the room key (mk)')
  const cek = crypto.getRandomValues(new Uint8Array(32))
  const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cekKey, enc.encode(String(plaintext))))
  return { v: VERSION, iv: b64(iv), ct: b64(ct), recipients: { room: await wrapSym(mk, cek) } }
}

/** Open a symmetric envelope with `mk` → the plaintext string, or null on wrong key / tamper / malformed (fail-closed). */
export async function open(envelope, { mk } = {}) {
  if (!isEnvelope(envelope) || !mk) return null
  const r = envelope.recipients.room
  try {
    const wk = await roomWrapKey(mk)
    const cek = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(r.iv) }, wk, ub64(r.w)))
    const cekKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['decrypt'])
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(envelope.iv) }, cekKey, ub64(envelope.ct)))
    return dec.decode(pt)
  } catch {
    return null
  }
}

/** True if a stored object is a v1 symmetric envelope with a room recipient. */
export function isEnvelope(o) {
  return !!(o && typeof o === 'object' && o.v === VERSION && typeof o.iv === 'string' && typeof o.ct === 'string' && o.recipients && o.recipients.room)
}

// ── Sealed box (PUBLIC-KEY) — used to seal each epoch key to each member's box key ────────────────────────────────────
// Anonymous sealed box: a fresh EPHEMERAL ECDH-P256 keypair per message → HKDF("sealedbox") → AES-256-GCM; the sender key
// is discarded, so the box reveals nothing about who sealed it. Only the recipient's PRIVATE key opens it.
const EC = { name: 'ECDH', namedCurve: 'P-256' }
async function boxKey(priv, pubJwk) {
  const privKey = priv && priv.kty ? await crypto.subtle.importKey('jwk', priv, EC, false, ['deriveBits']) : priv
  const pub = await crypto.subtle.importKey('jwk', pubJwk, EC, false, [])
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, privKey, 256)
  const ikm = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('sealedbox') }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}
/** Generate a recipient keypair → { publicJwk, privateJwk }. Publish publicJwk; hold privateJwk. */
export async function genRecipientKey() {
  const kp = await crypto.subtle.generateKey(EC, true, ['deriveBits'])
  return { publicJwk: await crypto.subtle.exportKey('jwk', kp.publicKey), privateJwk: await crypto.subtle.exportKey('jwk', kp.privateKey) }
}
/** Seal a string to a recipient PUBLIC key (jwk) → an anonymous sealed box. Encrypt-only. */
export async function sealTo(plaintext, recipientPublicJwk) {
  if (!recipientPublicJwk) throw new Error('sealTo needs the recipient public key')
  const eph = await crypto.subtle.generateKey(EC, true, ['deriveBits'])
  const key = await boxKey(eph.privateKey, recipientPublicJwk)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(String(plaintext))))
  const epk = await crypto.subtle.exportKey('jwk', eph.publicKey)
  return { v: VERSION, alg: 'box', epk: { x: epk.x, y: epk.y }, iv: b64(iv), ct: b64(ct) }
}
/** Open a sealed box with the recipient PRIVATE key (jwk) → plaintext string, or null (fail-closed). */
export async function openBox(box, recipientPrivateJwk) {
  if (!isBox(box) || !recipientPrivateJwk) return null
  try {
    const key = await boxKey(recipientPrivateJwk, { kty: 'EC', crv: 'P-256', x: box.epk.x, y: box.epk.y })
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(box.iv) }, key, ub64(box.ct)))
    return dec.decode(pt)
  } catch {
    return null
  }
}
export function isBox(o) {
  return !!(o && typeof o === 'object' && o.v === VERSION && o.alg === 'box' && o.epk && typeof o.epk.x === 'string' && typeof o.iv === 'string' && typeof o.ct === 'string')
}
