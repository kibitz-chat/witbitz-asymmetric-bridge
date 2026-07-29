// Drive the LIVE Bridge through the full asymmetric co-signed flow — proving the client shapes work against prod
// before any UI. Creates a throwaway bridge space. Run: node demo/live-e2e.mjs
import { mintIdentity, publicIdentity, openSpace, admit, makeCoSignedEntry, makeEntry, verifyEntry, openEntry, bridge } from './bridgeClient.js'

const BASE = process.env.BRIDGE_BASE || 'https://api.witbitz.chat/v1/bridge'
const api = bridge(BASE)
const space = 'sp-demo-live-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8)
const log = (ok, msg) => console.log(`${ok ? '✓' : '✗'} ${msg}`)

const emily = await mintIdentity('Emily')
const assistant = await mintIdentity("Emily's assistant")
const greg = await mintIdentity('Greg')

let m = await openSpace(space, emily)
await api.create(m); log(true, `created bridge space ${space}`)
m = await admit(m, emily, publicIdentity(assistant), { caps: ['read'] })        // read only
m = await admit(m, emily, publicIdentity(greg), { caps: ['read', 'submit'] })
await api.putMembers(space, m); log(true, `admitted assistant (read) + Greg (read,submit) — epoch ${m.epoch}`)

// the public record a reader checks — "[check this]"
const pub = await api.getMembers(space)
const asstRow = pub.members.find((x) => x.party === assistant.id)
log(asstRow.caps.join(',') === 'read', `public membership shows the assistant as read-only: [${asstRow.caps}]`)

// a co-signed crossing: assistant drafts, Emily approves
const e = await makeCoSignedEntry(m, emily, assistant, { content: 'Greg — renewal is up. Straight ask: $0.375/unit against a 500,000-unit annual minimum.' })
const r = await api.submit(space, e); log(typeof r.seq === 'number', `co-signed crossing accepted (seq ${r.seq})`)

// Greg reads + verifies both signatures + opens the body
const feed = await api.read(space)
const entry = feed.entries[0]
const v = await verifyEntry(m, entry)
log(v.ok && v.party.party === emily.id && v.drafter.party === assistant.id, 'Greg verifies: authored by the assistant, approved by Emily')
log((await openEntry(m, greg, entry)).startsWith('Greg — renewal'), 'Greg opens the body with his epoch key')
log((await openEntry(m, await mintIdentity('outsider'), entry)) === null, 'an outsider holds no key → unreachable')

// the read-only assistant tries to cross ALONE → the server refuses (403 no_submit_cap)
try { await api.submit(space, await makeEntry(m, assistant, { content: 'sneak' })); log(false, 'assistant solo submit UNEXPECTEDLY accepted') }
catch (err) { log(err.status === 403, `assistant solo submit refused by the server (${err.status} ${err.message})`) }

console.log('\nLIVE e2e complete.')
