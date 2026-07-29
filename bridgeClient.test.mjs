// Interop test: the browser bridgeClient's signatures must verify with the SERVER's verifier (agent/bridgeLog.mjs),
// and the asymmetric-demo invariants must hold. Runs in Node (the client uses only globals Node ≥20 also has).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { verifyAttribution as serverVerify, submit as serverSubmit, verifyMembershipUpdate as serverVerifyMembership, signMembership } from './server/bridgeLog.mjs'
import { mintIdentity, publicIdentity, openSpace, admit, revoke, recap, makeEntry, makeCoSignedEntry, verifyEntry, openEntry } from './bridgeClient.js'

test('web client ↔ server verifier: a co-signed crossing verifies, the read-only drafter can never cross alone, a body is unreachable without the key', async () => {
  const emily = await mintIdentity('Emily')                          // submit (approver)
  const assistant = await mintIdentity("Emily's assistant")          // read ONLY (drafter)
  const greg = await mintIdentity('Greg')                             // submit
  let m = await openSpace('sp-demo-interop', emily)                  // epoch 0
  m = await admit(m, emily, publicIdentity(assistant), { caps: ['read'] })         // epoch 1 — read only
  m = await admit(m, emily, publicIdentity(greg), { caps: ['read', 'submit'] })     // epoch 2

  const e = await makeCoSignedEntry(m, emily, assistant, { content: 'offer: $0.375 against a 500k annual commitment' })

  // (1) INTEROP — the SERVER's own verifier accepts a browser-built co-signed entry.
  assert.equal(await serverVerify(m, e), true, 'web co-signed entry verifies with agent/bridgeLog.mjs')
  assert.ok((await serverSubmit([], m, e, { now: 1 })).ok, 'and the server would accept it into the log')

  // (2) [check this] — both signatures resolve against the public membership.
  const v = await verifyEntry(m, e)
  assert.equal(v.ok, true); assert.equal(v.party.party, emily.id); assert.equal(v.drafter.party, assistant.id)

  // (3) the read-only assistant can NEVER cross anything alone.
  assert.equal((await serverSubmit([], m, await makeEntry(m, assistant, { content: 'sneak' }))).error, 'no_submit_cap')

  // (4) Greg holds the epoch key → he opens the body; a stranger holds no key → unreachable, not withheld.
  assert.equal(await openEntry(m, greg, e), 'offer: $0.375 against a 500k annual commitment')
  assert.equal(await openEntry(m, await mintIdentity('stranger'), e), null)

  // (5) a forged draft co-signature is rejected by both verifiers.
  const forged = { ...e, draft: { party: assistant.id, sig: 'AAAA' } }
  assert.equal((await verifyEntry(m, forged)).ok, false)
  assert.equal((await serverSubmit([], m, forged)).error, 'bad_signature')

  // (6) INTEGRITY — the signatures BIND the content: altering the body breaks both verifiers (present ≠ binding).
  const altered = { ...e, body: { ...e.body, ct: 'AAAA' } }
  assert.equal((await verifyEntry(m, altered)).ok, false, 'altered content fails client verify')
  assert.equal((await serverSubmit([], m, altered)).error, 'bad_signature', 'and the server refuses it')

  // (7) a co-signature naming a NON-MEMBER drafter is refused (attribution is not decorative).
  const nonMember = await mintIdentity('not-a-member')
  assert.equal((await serverSubmit([], m, await makeCoSignedEntry(m, emily, nonMember, { content: 'x' }))).error, 'bad_signature')

  // (8) MEMBERSHIP AUTHORIZATION — a browser-built admit is server-authorized; upgrading the read-only assistant is not.
  //     This is the "have Greg PUT a membership that upgrades the assistant" attack, refused by the SERVER's verifier.
  assert.equal(await serverVerifyMembership(m, await admit(m, emily, publicIdentity(nonMember))), true, 'a browser admit() carries server-valid auth')
  const upgrade = m.members.map((x) => (x.party === assistant.id ? { ...x, caps: ['read', 'submit'] } : x))
  const craft = async (signer) => { const next = { space: m.space, epoch: m.epoch + 1, members: upgrade }; next.auth = { party: signer.id, sig: await signMembership(signer.sign.priv, next) }; return next }
  assert.equal(await serverVerifyMembership(m, await craft(greg)), false, 'Greg (submit, not admit) cannot upgrade the assistant')
  assert.equal(await serverVerifyMembership(m, await craft(assistant)), false, 'the assistant cannot upgrade itself')
  assert.equal(await serverVerifyMembership(m, await craft(nonMember)), false, 'an outsider cannot rewrite membership')
  assert.equal(await serverVerifyMembership(m, { space: m.space, epoch: m.epoch + 1, members: upgrade }), false, 'and an unsigned PUT is refused')
})

// ── revocation's HONEST half: forward-secrecy protects the FUTURE, not the past. The credibility of the guarantee is
// precisely that it ISN'T absolute — a revoked party keeps what it already decrypted, and can never see what comes next.
test('revocation forward-secrecy: a revoked party keeps what it already saw, never sees the future', async () => {
  const emily = await mintIdentity('Emily'), rogue = await mintIdentity('rogue')
  let m = await openSpace('sp-revread', emily) // epoch 0
  m = await admit(m, emily, publicIdentity(rogue), { caps: ['read', 'submit'] }) // epoch 1 — rogue holds the e1 key
  const held = m // the membership record rogue holds WHILE a member (its retained key material)
  const oldEntry = await makeEntry(m, emily, { content: 'old — seen while rogue was a member' })
  assert.equal(await openEntry(held, rogue, oldEntry), 'old — seen while rogue was a member', 'rogue reads content sealed under the epoch key it holds')

  m = await revoke(m, emily, rogue.id) // epoch 2 — rogue removed; the e2 key is sealed only to emily
  const newEntry = await makeEntry(m, emily, { content: 'new — after the boundary' })

  assert.equal(await openEntry(held, rogue, oldEntry), 'old — seen while rogue was a member', "rogue STILL opens what it already held — you can't un-see")
  assert.equal(await openEntry(held, rogue, newEntry), null, 'but rogue was never sealed the new epoch key → the future is dark')
  assert.equal(await openEntry(m, rogue, oldEntry), null, 'and the post-revoke record grants rogue nothing (it is no longer a member)')
  assert.equal(await openEntry(m, emily, newEntry), 'new — after the boundary', 'emily, still a member, reads the new content')
})

// ── DOWNGRADE (recap) — distinct from revoke (eject): the member STAYS but loses a capability. Where a bug would be
// subtle rather than obvious. Greg keeps read + his epoch grant, loses submit: the server refuses his writes, he still reads.
test('downgrade (recap): a member stripped of submit but kept cannot write, still reads', async () => {
  const emily = await mintIdentity('Emily'), greg = await mintIdentity('Greg'), assistant = await mintIdentity('assistant')
  let m = await openSpace('sp-downgrade', emily)
  m = await admit(m, emily, publicIdentity(greg), { caps: ['read', 'submit'] })
  m = await admit(m, emily, publicIdentity(assistant), { caps: ['read'] })
  assert.ok((await serverSubmit([], m, await makeEntry(m, greg, { content: 'before' }))).ok, 'Greg posts while he holds submit')

  const before = m
  m = await recap(m, emily, greg.id, ['read']) // keep Greg, strip submit (a new epoch re-keyed to everyone incl. Greg)
  assert.equal(await serverVerifyMembership(before, m), true, 'the recap is an authorized successor (emily holds admit)')
  assert.deepEqual(m.members.find((x) => x.party === greg.id).caps, ['read'], 'Greg is still a member, now read-only')

  assert.equal((await serverSubmit([], m, await makeEntry(m, greg, { content: 'after' }))).error, 'no_submit_cap', 'the downgraded member cannot write')
  assert.equal(await openEntry(m, greg, await makeCoSignedEntry(m, emily, assistant, { content: 'shared after downgrade' })), 'shared after downgrade', 'but STILL reads new content — he kept read + the new epoch key')
})
