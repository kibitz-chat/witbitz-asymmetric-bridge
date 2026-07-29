// prepRoom.test.mjs — the PRIVATE half made checkable. The prep room is sealed to Emily; the assistant reasons over it;
// and — the point of the whole asymmetric demo — none of Emily's private material ever reaches a crossing.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mintIdentity } from './bridgeClient.js'
import { EMILY_BRIEF, PRIVATE_TOKENS, sealPrepRoom, openPrepRoom, assistantDraft } from './prepRoom.js'

test('the prep room is SEALED to Emily — only she opens it; Greg (or anyone) gets null, and the blob is opaque', async () => {
  const emily = await mintIdentity('Emily'), greg = await mintIdentity('Greg')
  const sealed = await sealPrepRoom(emily)
  assert.deepEqual(await openPrepRoom(emily, sealed), EMILY_BRIEF, 'Emily opens her own prep room')
  assert.equal(await openPrepRoom(greg, sealed), null, 'Greg holds no key for it → null, never the brief')
  for (const t of PRIVATE_TOKENS) assert.equal(JSON.stringify(sealed).includes(t), false, `the sealed blob leaks no plaintext ("${t}")`)
})

test('the assistant DRAFTS from the brief — grounded in its numbers, stating NONE of the private tokens', async () => {
  const brief = EMILY_BRIEF
  for (let round = 0; round <= 2; round++) {
    const { draft } = assistantDraft(brief, Array(round).fill({ text: 'a reply' }))
    assert.ok(draft.includes(brief.target) || draft.includes(brief.midpoint), `round ${round}: the draft proposes a price FROM the brief`)
    for (const t of PRIVATE_TOKENS) assert.equal(draft.includes(t), false, `round ${round}: the crossing must NOT contain "${t}"`)
  }
  // …yet the assistant DID reason over the private material: its note (Emily's eyes only) cites the ceiling + the leverage.
  const { note } = assistantDraft(brief, [])
  assert.ok(note.includes(brief.ceiling), 'the private note cites the absolute ceiling')
  assert.ok(note.includes('Ferndale'), 'and the reason to close that Greg must never learn')
})

test('sanity: the private tokens really are in the brief (so "absent from the crossing" is a guarantee, not a typo)', () => {
  const blob = JSON.stringify(EMILY_BRIEF)
  for (const t of PRIVATE_TOKENS) assert.ok(blob.includes(t), `the brief contains "${t}" — it is real private material`)
})
