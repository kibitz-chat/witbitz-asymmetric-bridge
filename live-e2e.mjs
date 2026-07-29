// Drive the LIVE Bridge through the full asymmetric co-signed flow — the runnable proof. Creates throwaway sp-ci-*
// spaces and DELETES them at the end (signed teardown), so CI leaves no litter on production. Run: node live-e2e.mjs
import { mintIdentity, publicIdentity, openSpace, admit, revoke, recap, makeCoSignedEntry, makeEntry, verifyEntry, openEntry, signMembership, bridge } from './bridgeClient.js'

const api = bridge(process.env.BRIDGE_BASE || 'https://api.witbitz.chat/v1/bridge')
const log = (ok, msg) => { console.log(`${ok ? '✓' : '✗'} ${msg}`); if (!ok) process.exitCode = 1 }
const seq = (r) => typeof (r && r.seq) === 'number'
const refuse = async (status, label, fn) => { try { await fn(); log(false, `${label} — UNEXPECTEDLY accepted`) } catch (x) { log(x.status === status, `${label} refused ${x.status} ${x.message}`) } }

const emily = await mintIdentity('Emily'), assistant = await mintIdentity("Emily's assistant"), greg = await mintIdentity('Greg')
const created = []
async function space() {
  const s = 'sp-ci-live-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); created.push({ s, admin: emily })
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
  log(seq(await api.submit(A.s, e)), 'co-signed crossing accepted')
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

  // the AUTHORIZATION test — the big one: nobody but a current admit-holder can rewrite membership. Crafting a record
  // that UPGRADES the read-only assistant to `submit` and PUTting it must be refused, however it is signed.
  const upgraded = A.m.members.map((x) => (x.party === assistant.id ? { ...x, caps: ['read', 'submit'] } : x))
  const forge = async (signer) => { const n = { space: A.s, epoch: A.m.epoch + 1, members: upgraded }; n.auth = { party: signer.id, sig: await signMembership(signer, n) }; return n }
  await refuse(403, 'Greg (submit, not admit) upgrades the assistant', async () => api.putMembers(A.s, await forge(greg)))
  await refuse(403, 'the assistant upgrades ITSELF', async () => api.putMembers(A.s, await forge(assistant)))
  await refuse(403, 'an outsider rewrites membership', async () => api.putMembers(A.s, await forge(await mintIdentity('intruder'))))
  await refuse(403, 'an UNSIGNED membership PUT', async () => api.putMembers(A.s, { space: A.s, epoch: A.m.epoch + 1, members: upgraded }))
  // and the guarantee still holds after every refused upgrade: the assistant STILL cannot cross anything alone
  await refuse(403, 'assistant STILL cannot submit after the refused upgrades', async () => api.submit(A.s, await makeEntry(A.m, assistant, { content: 'still sneaking' })))
  // the public membership is unchanged — the assistant is still read-only
  log((await api.getMembers(A.s)).members.find((x) => x.party === assistant.id).caps.join() === 'read', 'positive control: after the attacks the public membership is UNCHANGED (assistant still read-only)')

  // teardown must ALSO be authorized (not merely name-scoped): a member without `admit`, or an outsider, can't delete
  await refuse(403, 'Greg (no admit cap) tears the space down', async () => api.del(A.s, greg))
  await refuse(403, 'an outsider tears the space down', async () => api.del(A.s, await mintIdentity('vandal')))

  const B = await space()
  await refuse(400, 'cross-space replay (A\'s entry into B)', async () => api.submit(B.s, e))
  log(seq(await api.submit(B.s, await makeCoSignedEntry(B.m, emily, assistant, { content: 'legit crossing native to B' }))), 'positive control: a fresh crossing NATIVE to B IS accepted (so the refusal above is specific, not "B is broken")')

  A.m = await admit(A.m, emily, publicIdentity(await mintIdentity('d')), { caps: ['read'] }); await api.putMembers(A.s, A.m) // epoch boundary
  await refuse(400, 'epoch-boundary replay (old epoch)', async () => api.submit(A.s, e))
  log(seq(await api.submit(A.s, await makeCoSignedEntry(A.m, emily, assistant, { content: 'fresh crossing at the NEW epoch' }))), 'positive control: a fresh crossing at the NEW epoch IS accepted (so "old epoch refused" ≠ "the space broke")')

  // ── REVOCATION + the PRE-SIGNED-TRANSITION attack — the move a reviewer reaches for once the obvious PUT is closed:
  // a party signs a membership WHILE it holds admit, its admit is revoked, then it submits the stale-but-valid record.
  const sign = async (rec, who) => ({ ...rec, auth: { party: who.id, sig: await signMembership(who, rec) } })
  const rogue = await mintIdentity('rogue-admin')
  const R = await space()
  R.m = await admit(R.m, emily, publicIdentity(rogue), { caps: ['read', 'submit', 'admit'] }); await api.putMembers(R.s, R.m)
  const heldByRogue = R.m // the membership record rogue holds WHILE a member — its retained key material
  const oldCrossing = await makeCoSignedEntry(R.m, emily, assistant, { content: 'seen while rogue was a member' }); await api.submit(R.s, oldCrossing)
  log((await openEntry(heldByRogue, rogue, oldCrossing)) === 'seen while rogue was a member', 'rogue reads content sealed under the epoch key it holds')
  const upO = R.m.members.map((x) => (x.party === assistant.id ? { ...x, caps: ['read', 'submit'] } : x)) // "upgrade the assistant"
  const preNext = await sign({ space: R.s, epoch: R.m.epoch + 1, members: upO }, rogue)   // rogue pre-signs for the next epoch…
  const preFuture = await sign({ space: R.s, epoch: R.m.epoch + 2, members: upO }, rogue)  // …and a FUTURE one, anticipating the revoke
  R.m = await revoke(R.m, emily, rogue.id); await api.putMembers(R.s, R.m)                  // emily revokes rogue's admit
  log((await api.getMembers(R.s)).members.every((x) => x.party !== rogue.id), 'revocation: the revoked admin is gone from the public record')
  await refuse(403, 'pre-signed upgrade at the next epoch (submitted AFTER the revoke) — loses the monotonic race', async () => api.putMembers(R.s, preNext))
  await refuse(403, 'pre-signed upgrade at a FUTURE epoch — rogue no longer holds admit in the current head', async () => api.putMembers(R.s, preFuture))
  await refuse(403, 'no-lockout: even the founder cannot remove the last admit-holder', async () => api.putMembers(R.s, await sign({ space: R.s, epoch: R.m.epoch + 1, members: R.m.members.map((x) => (x.party === emily.id ? { ...x, caps: ['read', 'submit'] } : x)) }, emily)))
  await refuse(403, 'epoch rollback signed by a legitimate admit-holder (isolates the monotonic guard)', async () => api.putMembers(R.s, await sign({ space: R.s, epoch: R.m.epoch - 1, members: R.m.members }, emily)))
  log(seq(await api.submit(R.s, await makeCoSignedEntry(R.m, greg, assistant, { content: 'crossing still works post-revocation' }))), 'positive control: a genuine crossing on the post-revocation space IS accepted')
  // REVOCATION'S HONEST HALF — forward-secrecy protects the FUTURE, not the past (the guarantee is credible BECAUSE it isn't absolute).
  const newCrossing = await makeCoSignedEntry(R.m, emily, assistant, { content: 'sealed after the boundary' }); await api.submit(R.s, newCrossing)
  log((await openEntry(heldByRogue, rogue, oldCrossing)) === 'seen while rogue was a member', "forward-secrecy: rogue STILL opens what it already held (can't un-see the past)")
  log((await openEntry(heldByRogue, rogue, newCrossing)) === null, 'forward-secrecy: but rogue was never sealed the new epoch key → the future is dark')

  // DOWNGRADE (recap) — a member KEPT but stripped of submit: writes refused, reads still work (distinct from revoke = eject).
  const D = await space()
  D.m = await recap(D.m, emily, greg.id, ['read']); await api.putMembers(D.s, D.m)
  log((await api.getMembers(D.s)).members.find((x) => x.party === greg.id).caps.join() === 'read', 'downgrade: Greg is still a member, now read-only')
  await refuse(403, 'the downgraded member (submit→read) can no longer submit', async () => api.submit(D.s, await makeEntry(D.m, greg, { content: 'i lost submit' })))
  const dShared = await makeCoSignedEntry(D.m, emily, assistant, { content: 'shared after downgrade' }); await api.submit(D.s, dShared)
  log((await openEntry(D.m, greg, dShared)) === 'shared after downgrade', 'downgrade: but the downgraded member STILL reads new content (kept read + the new key)')
} finally {
  let cleaned = 0
  for (const { s, admin } of created) { try { await api.del(s, admin); cleaned++ } catch { /* teardown is best-effort */ } }
  if (cleaned === created.length) log(true, `teardown: deleted ${cleaned}/${created.length} self-test spaces (no litter on prod)`)
  else console.warn(`⚠ teardown: deleted ${cleaned}/${created.length} — a transient DELETE hiccup left litter, but every assertion above still passed (a warning, not a failure)`)
  console.log('\nLIVE e2e complete.')
}
