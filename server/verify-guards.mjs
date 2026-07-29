// server/verify-guards.mjs — MUTATION check for the Bridge's security guards. The bug we shipped (an unauthenticated
// membership PUT could upgrade a read-only party) survived 26 green tests because the guard DID NOT EXIST and nothing
// noticed its absence. A passing suite proves the tests pass; it does NOT prove any given check is load-bearing.
//
// This harness proves it directly: for each named security check, it DELETES the check (a structure-preserving edit),
// re-runs the full Bridge suite, and asserts the suite now FAILS. A guard whose removal keeps the suite green is a guard
// with no test — reported as SURVIVED and the run exits non-zero. Restores every file (even on crash). No deps.
//
//   node server/verify-guards.mjs
import { readFileSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const TESTS = ['server/bridgeLog.test.mjs', 'server/bridgeMembership.test.mjs', 'server/bridgeSpace.test.mjs', 'server/bridgeHandler.test.mjs', 'server/bridge.adversary.test.mjs', 'server/bridge.revocation.test.mjs', 'bridgeClient.test.mjs']

// Each entry NEUTRALIZES one security check. `find` must occur EXACTLY once (a 0/2 count means the guard moved and this
// harness is stale — itself a failure). `replace` keeps the code syntactically valid but strips the check's effect.
const GUARDS = [
  { name: 'handler · create is a signed genesis (verifyCreate)', file: 'server/bridgeHandler.mjs',
    find: "if (!(await verifyCreate(m))) return json(403, { error: 'unauthorized_create' })",
    replace: "if (false) return json(403, { error: 'unauthorized_create' })" },
  { name: 'handler · membership PUT is authorized (verifyMembershipUpdate)', file: 'server/bridgeHandler.mjs',
    find: "if (!(await verifyMembershipUpdate(state.membership, m))) return json(403, { error: 'unauthorized_update' })",
    replace: "if (false) return json(403, { error: 'unauthorized_update' })" },
  { name: 'handler · membership PUT is an atomic compare-and-set (409 on a lost race)', file: 'server/bridgeHandler.mjs',
    find: "if (!(await store.putMembership(space, m, { ifEpoch: state.membership.epoch }))) return json(409, { error: 'conflict' })",
    replace: "await store.putMembership(space, m, { ifEpoch: state.membership.epoch })" },
  { name: 'handler · DELETE teardown is authorized (verifyDelete)', file: 'server/bridgeHandler.mjs',
    find: "if (!(await verifyDelete(st.membership, parseDeleteAuth(event), { now: nowMs() }))) return json(403, { error: 'unauthorized_delete' })",
    replace: "if (false) return json(403, { error: 'unauthorized_delete' })" },
  { name: 'handler · DELETE namespace boundary (sp-ci-* only)', file: 'server/bridgeHandler.mjs',
    find: "if (!/^sp-ci-/.test(space)) return json(403, { error: 'protected' })",
    replace: "if (false) return json(403, { error: 'protected' })" },
  { name: 'submit · submit-capability gate', file: 'server/bridgeLog.mjs',
    find: "if (!m.caps.includes('submit')) return { ok: false, error: 'no_submit_cap' }",
    replace: "if (false) return { ok: false, error: 'no_submit_cap' }" },
  { name: 'submit · entry is bound to its space', file: 'server/bridgeLog.mjs',
    find: "if (entry.space !== membership.space) return { ok: false, error: 'wrong_space' }",
    replace: "if (false) return { ok: false, error: 'wrong_space' }" },
  { name: 'submit · entry is bound to the current epoch', file: 'server/bridgeLog.mjs',
    find: "if (entry.epoch !== membership.epoch) return { ok: false, error: 'wrong_epoch' }",
    replace: "if (false) return { ok: false, error: 'wrong_epoch' }" },
  { name: 'submit · signature attribution', file: 'server/bridgeLog.mjs',
    find: "if (!(await verifyAttribution(membership, entry))) return { ok: false, error: 'bad_signature' }",
    replace: "if (false) return { ok: false, error: 'bad_signature' }" },
  { name: 'submit · replay (party,nonce) dedup', file: 'server/bridgeLog.mjs',
    find: "if (log.some((x) => x.party === entry.party && x.nonce === entry.nonce)) return { ok: false, error: 'replay' }",
    replace: "if (false) return { ok: false, error: 'replay' }" },
  { name: 'membership-update · epoch monotonicity', file: 'server/bridgeLog.mjs',
    find: '!(next.epoch > cur.epoch)', replace: 'false' },
  { name: 'membership-update · no-lockout (≥1 admit remains)', file: 'server/bridgeLog.mjs',
    find: "if (!next.members.some((x) => Array.isArray(x.caps) && x.caps.includes('admit'))) return false",
    replace: "if (false) return false" },
  { name: 'membership-update · admit-capability gate', file: 'server/bridgeLog.mjs',
    find: "  const actor = cur.members.find((x) => x.party === next.auth.party) // authority = the CURRENT head, re-checked at apply time\n  if (!actor || !actor.caps.includes('admit')) return false",
    replace: '  const actor = cur.members.find((x) => x.party === next.auth.party) // authority = the CURRENT head, re-checked at apply time' },
  { name: 'membership-update · signature binding', file: 'server/bridgeLog.mjs',
    find: 'return verifyStr(actor.signPub, next.auth.sig, membershipCore(next))', replace: 'return true' },
  { name: 'delete-auth · admit-capability gate', file: 'server/bridgeLog.mjs',
    find: "  const actor = membership.members.find((x) => x.party === auth.party)\n  if (!actor || !actor.caps.includes('admit')) return false",
    replace: '  const actor = membership.members.find((x) => x.party === auth.party)' },
  { name: 'delete-auth · freshness (ts window)', file: 'server/bridgeLog.mjs',
    find: 'if (!(Math.abs(now - auth.ts) <= maxSkewMs)) return false',
    replace: 'if (false) return false' },
]

const suiteFails = () => { // true ⇒ at least one test failed (the guard's removal was CAUGHT)
  try { execFileSync('node', ['--test', ...TESTS], { cwd: ROOT, stdio: 'pipe' }); return false } catch { return true }
}

const originals = new Map() // file → pristine contents, restored in finally
const read = (f) => { if (!originals.has(f)) originals.set(f, readFileSync(resolve(ROOT, f), 'utf8')); return originals.get(f) }
const restoreAll = () => { for (const [f, txt] of originals) writeFileSync(resolve(ROOT, f), txt) }

let failures = 0
try {
  process.stdout.write('baseline (unmutated suite must be green) … ')
  if (suiteFails()) { console.log('RED — fix the suite before mutation-testing'); process.exit(1) }
  console.log('green\n')
  console.log('Removing each security guard and asserting the suite catches it:\n')
  for (const g of GUARDS) {
    const src = read(g.file)
    const n = src.split(g.find).length - 1
    if (n !== 1) { console.log(`  ⚠ STALE   ${g.name}  (guard text found ${n}×, expected 1 — update this harness)`); failures++; continue }
    writeFileSync(resolve(ROOT, g.file), src.replace(g.find, g.replace))
    const caught = suiteFails()
    writeFileSync(resolve(ROOT, g.file), src) // restore immediately
    console.log(`  ${caught ? '✅ CAUGHT  ' : '❌ SURVIVED'} ${g.name}`)
    if (!caught) failures++
  }
} finally { restoreAll() }

console.log(`\n${failures ? `✗ ${failures} guard(s) are NOT load-bearing (or the harness is stale).` : `✓ all ${GUARDS.length} guards are load-bearing — removing any one turns the suite red.`}`)
process.exit(failures ? 1 : 0)
