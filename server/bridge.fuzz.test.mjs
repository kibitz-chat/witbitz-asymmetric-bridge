// agent/bridge.fuzz.test.mjs — PROPERTY + DIFFERENTIAL fuzzing of the Bridge server. Hand-written tests cover the cases
// we thought of; a fuzzer explores the ones we didn't. A spec-derived ORACLE (accept iff the INVARIANT holds — derived
// from docs/bridge-protocol.md, NOT copied from the handler) is checked against the real handler over hundreds of random
// inputs. Any divergence is a bug in one of them. Deterministic by default (fixed seed) so a failure reproduces; set
// FUZZ_SEED / FUZZ_N to widen. Validity is known BY CONSTRUCTION (we sign correctly, corrupt, or omit), so the oracle
// never re-implements the crypto — it reasons about the invariant.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { genPartyIdentity, publicIdentity, openSpace, admit } from './bridgeMembership.mjs'
import { makeEntry, makeCoSignedEntry, signMembership, genServerKey } from './bridgeLog.mjs'
import { handleBridgeHttp } from './bridgeHandler.mjs'

const SEED = Number(process.env.FUZZ_SEED || 0x1234beef) >>> 0
const N = Number(process.env.FUZZ_N || 250)
function mulberry32(seed) { let s = seed >>> 0; return () => { s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296 } }
const r = mulberry32(SEED)
const pick = (a) => a[Math.floor(r() * a.length)]
const corrupt = (s) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1) // flip one char ⇒ an invalid signature

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
const status = async (method, path, body, query) => (await handleBridgeHttp(ev(method, path, body, query), deps)).statusCode
const BODY = { v: 1, alg: 'gcm', iv: 'AAAA', ct: 'AAAA' }

const A = await genPartyIdentity(), O = await genPartyIdentity(), G = await genPartyIdentity(), stranger = await genPartyIdentity()
const ID = { [A.id]: A, [O.id]: O, [G.id]: G, [stranger.id]: stranger }
async function found(space) {
  let m = await openSpace(space, A); await status('POST', '/bridge/spaces', m)
  m = await admit(m, A, publicIdentity(O), { caps: ['read'] })
  m = await admit(m, A, publicIdentity(G), { caps: ['read', 'submit'] })
  await status('PUT', `/bridge/spaces/${space}/members`, m); return m
}

// PROPERTY 1 · MEMBERSHIP DIFFERENTIAL + MONOTONICITY WALK — a random walk of membership PUTs; the handler must accept
// EXACTLY when a current admit-holder signed a strictly-greater epoch, and every accepted step must advance the epoch.
test(`fuzz: membership updates — handler ⇔ oracle over a monotonicity walk (seed ${SEED.toString(16)}, N=${N})`, async () => {
  const space = 'sp-fz-mem'; let cur = await found(space)
  for (let i = 0; i < N; i++) {
    const signer = pick([A, O, G, stranger])
    const epoch = cur.epoch + pick([-1, 0, 1, 2])
    const caps = ['read', ...(r() < 0.5 ? ['submit'] : []), ...(r() < 0.3 ? ['admit'] : []), ...(r() < 0.2 ? ['revoke'] : [])]
    const tgt = pick([O.id, G.id]) // never re-cap A → keep a stable admit anchor for coverage of the accept path
    const members = cur.members.map((x) => (x.party === tgt ? { ...x, caps } : x))
    const sigMode = pick(['valid', 'corrupt', 'missing'])
    const next = { space, epoch, members }
    if (sigMode !== 'missing') { const sig = await signMembership(signer.sign.priv, next); next.auth = { party: signer.id, sig: sigMode === 'corrupt' ? corrupt(sig) : sig } }

    const actor = cur.members.find((x) => x.party === signer.id) // ORACLE (the invariant, stated from the spec):
    const oracle = sigMode === 'valid' && !!actor && actor.caps.includes('admit') && epoch > cur.epoch && members.some((x) => x.caps.includes('admit'))
    const accepted = (await status('PUT', `/bridge/spaces/${space}/members`, next)) === 200
    const why = `seed=${SEED.toString(16)} i=${i} signer=${signer === A ? 'A' : signer === O ? 'O' : signer === G ? 'G' : 'stranger'} Δepoch=${epoch - cur.epoch} sig=${sigMode}`
    assert.equal(accepted, oracle, why)
    if (accepted) { assert.ok(epoch > cur.epoch, `accepted a non-advancing epoch — ${why}`); assert.ok(actor.caps.includes('admit'), `accepted an update from a non-admit signer — ${why}`); cur = next }
  }
})

// PROPERTY 2 · ENTRY DIFFERENTIAL — random entries (right/wrong space, right/wrong epoch, valid/tampered sig, no/member/
// non-member co-signature); the handler must accept EXACTLY when the party is a submit-capable member, the context binds,
// and every signature verifies. Fresh nonces ⇒ replay never fires (covered elsewhere), so the oracle omits it.
test(`fuzz: entries — handler ⇔ oracle over random malformations (seed ${SEED.toString(16)}, N=${N})`, async () => {
  const space = 'sp-fz-ent'; const m = await found(space); const EP = m.epoch
  const hasSubmit = (id) => m.members.find((x) => x.party === id)?.caps.includes('submit')
  for (let i = 0; i < N; i++) {
    const party = pick([A, O, G, stranger])
    const badSpace = r() < 0.25, badEpoch = r() < 0.25, tampered = r() < 0.3
    const draft = pick(['none', 'member', 'nonmember'])
    const es = badSpace ? 'sp-fz-other' : space, ee = badEpoch ? EP + 3 : EP
    let entry = draft === 'none'
      ? await makeEntry(party, { space: es, epoch: ee, body: BODY })
      : await makeCoSignedEntry(party, draft === 'member' ? O : stranger, { space: es, epoch: ee, body: BODY })
    if (tampered) entry = { ...entry, body: { ...BODY, ct: 'T' + i } } // breaks the signature over the core

    const oracle = !!hasSubmit(party.id) && !badSpace && !badEpoch && !tampered && draft !== 'nonmember'
    const accepted = (await status('POST', `/bridge/spaces/${space}/entries`, entry)) === 201
    assert.equal(accepted, oracle, `seed=${SEED.toString(16)} i=${i} party=${party === A ? 'A' : party === O ? 'O' : party === G ? 'G' : 'stranger'} badSpace=${badSpace} badEpoch=${badEpoch} tampered=${tampered} draft=${draft}`)
  }
})

// PROPERTY 3 · ROBUSTNESS — structurally-malformed input must never crash the server (no 5xx) and never sneak an
// accept: a request whose body isn't a well-formed, authorized membership/entry is refused, never 2xx-accepted.
test(`fuzz: malformed input never 5xx and never a bogus accept (seed ${SEED.toString(16)}, N=${N})`, async () => {
  const space = 'sp-fz-rob'; await found(space)
  const junk = () => pick([undefined, null, 42, 'a string', [], {}, { members: 'not-an-array' }, { space, epoch: 'NaN', members: [] }, { space, members: [{}], auth: 123 }, { space, epoch: -5, members: [], auth: { party: 'x', sig: 'y' } }, { deeply: { nested: { a: [1, 2, 3] } } }, { space: 'sp-fz-other', epoch: 99, members: [] }])
  for (let i = 0; i < N; i++) {
    const route = pick([['PUT', `/bridge/spaces/${space}/members`], ['POST', `/bridge/spaces/${space}/entries`], ['POST', '/bridge/spaces'], ['DELETE', `/bridge/spaces/${space}`], ['GET', `/bridge/spaces/${space}/members`]])
    const st = await status(route[0], route[1], junk())
    assert.ok(st < 500, `seed=${SEED.toString(16)} i=${i} ${route[0]} ${route[1]} → ${st} (server error on malformed input)`)
    if (route[0] === 'PUT' || (route[0] === 'POST' && route[1].endsWith('/entries'))) assert.ok(st !== 200 && st !== 201, `malformed ${route[0]} was ACCEPTED (${st})`)
  }
})
