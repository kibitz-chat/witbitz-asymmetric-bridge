import { test } from 'node:test'
import assert from 'node:assert/strict'
import { genPartyIdentity, publicIdentity, openSpace, admit, epochKey } from './bridgeMembership.mjs'
import { genServerKey, verifyCheckpoint, chainMatchesCheckpoint } from './bridgeLog.mjs'
import { createService, serviceCheckpoint, partySubmit, partyRead } from './bridgeSpace.mjs'

// A = a NATIVE party (a witbitz comedian's Space, conceptually). X = an EXTERNAL party — it holds ONLY an identity and
// speaks the protocol crypto; it runs NO witbitz Space code. This is the interop proof: the two are first-class
// co-inhabitants of one shared space, governed + attributed + content-blind to the platform.
const A = await genPartyIdentity() // native founder
const X = await genPartyIdentity() // external party (someone else's agent + humans, elsewhere)
const server = await genServerKey() // the platform's checkpoint key

test('interop: a NATIVE and an EXTERNAL party co-inhabit one shared space, governed + content-blind', async () => {
  let m = await openSpace('sp-bridge-interop', A)
  m = await admit(m, A, publicIdentity(X)) // epoch 1: A + X (read+submit)
  let svc = createService('sp-bridge-interop', m, server)

  // X (external) submits — seals under the shared epoch key it opened, signs with ITS OWN key.
  let r = await partySubmit(svc, X, { content: 'From our side: we can do net-30 if you cover freight.', kind: 'load', actor: 'agent', now: 1 })
  assert.ok(r.ok, r.error); svc = r.svc
  // A (native) replies.
  r = await partySubmit(svc, A, { content: 'Deal on net-30 — split freight 50/50?', kind: 'post', actor: 'human', now: 2 })
  assert.ok(r.ok, r.error); svc = r.svc

  // A reads: both decrypt (shared epoch key) + verify (attributed to the right party).
  const asA = await partyRead(svc, A)
  assert.equal(asA.length, 2)
  assert.equal(asA[0].from, X.id); assert.equal(asA[0].attributed, true); assert.match(asA[0].content, /net-30/)
  assert.equal(asA[1].from, A.id); assert.equal(asA[1].attributed, true)
  // X reads the same shared thread.
  assert.equal((await partyRead(svc, X))[1].content, 'Deal on net-30 — split freight 50/50?')

  // The platform is content-blind: the stored bodies are ciphertext — no plaintext anywhere in the log.
  assert.equal(JSON.stringify(svc.log).includes('net-30'), false, 'plaintext never appears in the stored log')

  // Trustless audit: a signed checkpoint both parties verify + pin.
  const cp = await serviceCheckpoint(svc, { now: 3 })
  assert.equal(await verifyCheckpoint(server.pub, cp), true)
  assert.equal(await chainMatchesCheckpoint(svc.log, cp), true)
})

test('confinement + governance hold for the external party', async () => {
  let m = await openSpace('sp-bridge-interop-2', A)
  m = await admit(m, A, publicIdentity(X)) // epoch 1
  const svc = createService('sp-bridge-interop-2', m, server)
  // a stranger never admitted holds no epoch key → cannot submit (confinement by key, not policy).
  const stranger = await genPartyIdentity()
  await assert.rejects(() => partySubmit(svc, stranger, { content: 'sneak in' }), /no current epoch key/)
  // X, admitted at epoch 1, cannot open epoch-0 content it was never present for (no back-history).
  assert.equal(await epochKey(m, X, 0), null)
})
