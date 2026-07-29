// Drive the LIVE Bridge through the full asymmetric co-signed flow — the runnable proof. Creates throwaway sp-ci-*
// spaces and DELETES them at the end (teardown), so CI leaves no litter on production. Run: node live-e2e.mjs
import { mintIdentity, publicIdentity, openSpace, admit, makeCoSignedEntry, makeEntry, verifyEntry, openEntry, bridge } from './bridgeClient.js'

const api = bridge(process.env.BRIDGE_BASE || 'https://api.witbitz.chat/v1/bridge')
const log = (ok, msg) => { console.log(`${ok ? '✓' : '✗'} ${msg}`); if (!ok) process.exitCode = 1 }
const refuse = async (status, label, fn) => { try { await fn(); log(false, `${label} — UNEXPECTEDLY accepted`) } catch (x) { log(x.status === status, `${label} refused ${x.status} ${x.message}`) } }

const emily = await mintIdentity('Emily'), assistant = await mintIdentity("Emily's assistant"), greg = await mintIdentity('Greg')
const created = []
async function space() {
  const s = 'sp-ci-live-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); created.push(s)
  let m = await openSpace(s, emily); await api.create(m)
  m = await admit(m, emily, publicIdentity(assistant), { caps: ['read'] })          // read · cannot post
  m = await admit(m, emily, publicIdentity(greg), { caps: ['read', 'submit'] })
  await api.putMembers(s, m); return { s, m }
}

try {
  const A = await space()
  log(true, `bridge space ${A.s} — assistant read-only, Greg read+submit (epoch ${A.m.epoch})`)
  log((await api.getMembers(A.s)).members.find((x) => x.party === assistant.id).caps.join() === 'read', 'public membership: the assistant is read-only  ("[check this]")')

  // the happy path: a co-signed crossing (assistant drafts, Emily approves + signs)
  const e = await makeCoSignedEntry(A.m, emily, assistant, { content: 'Greg — renewal is up. $0.375/unit against a 500,000-unit annual minimum.' })
  log(typeof (await api.submit(A.s, e)).seq === 'number', 'co-signed crossing accepted')
  const entry = (await api.read(A.s)).entries[0]
  const v = await verifyEntry(A.m, entry)
  log(v.ok && v.party.party === emily.id && v.drafter.party === assistant.id, 'both signatures verify: authored by the assistant, approved by Emily')
  log((await openEntry(A.m, greg, entry)).startsWith('Greg'), 'Greg opens the body with the key his link carries')
  log((await openEntry(A.m, await mintIdentity('outsider'), entry)) === null, 'the feed is public ciphertext; an outsider holds no key → the BODY is unreachable (not the space)')

  // the negatives — capability, integrity, attribution, replay (each refused by the SERVER)
  await refuse(403, 'read-only assistant solo submit', async () => api.submit(A.s, await makeEntry(A.m, assistant, { content: 'sneak' })))
  await refuse(400, 'tampered body (signatures BIND content)', async () => { const t = await makeCoSignedEntry(A.m, emily, assistant, { content: 'x' }); t.body = { iv: t.body.iv, ct: 'dGFtcGVyZWQ' }; return api.submit(A.s, t) })
  await refuse(400, 'non-member drafter (attribution is enforced)', async () => api.submit(A.s, await makeCoSignedEntry(A.m, emily, await mintIdentity('not-a-member'), { content: 'x' })))
  await refuse(400, 'replay-append (re-submit a valid entry)', async () => api.submit(A.s, e))
  const B = await space()
  await refuse(400, 'cross-space replay (A\'s entry into B)', async () => api.submit(B.s, e))
  A.m = await admit(A.m, emily, publicIdentity(await mintIdentity('d')), { caps: ['read'] }); await api.putMembers(A.s, A.m) // epoch boundary
  await refuse(400, 'epoch-boundary replay (old epoch)', async () => api.submit(A.s, e))
} finally {
  let cleaned = 0
  for (const s of created) { try { await api.del(s); cleaned++ } catch { /* teardown is best-effort */ } }
  log(cleaned === created.length, `teardown: deleted ${cleaned}/${created.length} self-test spaces (no litter on prod)`)
  console.log('\nLIVE e2e complete.')
}
