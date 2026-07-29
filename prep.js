// prep.js — Emily's seat: the private prep room. Founds the Bridge, mints the parties, admits the assistant as
// read-only, and crosses only what Emily approves + signs (a CO-SIGNED entry). All keys stay in this browser.
import { mintIdentity, publicIdentity, openSpace, admit, makeCoSignedEntry, verifyEntry, openEntry, bridge } from './bridgeClient.js'
const BASE = 'https://api.witbitz.chat/v1/bridge'
const api = bridge(BASE)
const $ = (id) => document.getElementById(id)
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]))

const BRIEF = `Need ≤ $0.395 to hold margin on the Ferndale wholesale contract.
Absolute ceiling $0.415. Ridgeline quoted $0.40 but six-week lead — a real
problem in Q4; don't want to switch mid-ramp.
Greg doesn't know about Ferndale (volume rising ~40%, we're locked to deliver).`

// The scripted assistant: a private reasoning note + a draft, per round.
const SCRIPT = [
  { note: `Your leverage is <b>volume, not price history</b>. A firm higher annual minimum is worth real money to a family firm with idle capacity — and it costs you nothing, since Ferndale guarantees the volume. Open at $0.375 against 500k. Mention the $0.40 quote as a market reference, not a threat.`,
    draft: `Greg — renewal's up and I'd like to keep it with you. Straight ask: $0.375 a unit. In exchange I'll commit to a 500,000-unit annual minimum, up from the 350,000 we've been running. That's real certainty for your production planning. I've got a $0.40 quote in hand, but I'd rather not move — you've never missed a delivery in four years and that's worth something. Can you work with the volume?` },
  { note: `He moved 1.5¢ on the first exchange and <b>volunteered a capacity constraint</b> he didn't have to. That's a supplier who wants this closed. The eight-week lead is the real cost — it collides with the Ferndale ramp. Trade price for schedule: ask $0.395 with a four-week Q4 lead, and offer to place the Q4 order early so he builds it into October instead of around it.`,
    draft: `That works on the volume, thanks. Let's meet nearer the middle on price — $0.395 — but the lead time is what matters to me in Q4: I need four weeks, not eight. Here's the trade: I'll place the Q4 order early, by September, so you can build it into your October run instead of around it. Does $0.395 at a four-week lead work if you have the order in hand by then?` },
  { note: `Close. He's near $0.395 with a five-week lead if you order by Sept 1 — under your ceiling, and the schedule fits the ramp. Take it.`,
    draft: `Deal — $0.395, five-week lead, I'll have the Q4 order to you by September 1. Appreciate you working the schedule with me. I'll send the paperwork this week.` },
]

let emily, assistant, greg, m, space, round = 0, gregCount = 0, lastLen = -1

async function setup() {
  $('brief').textContent = BRIEF
  emily = await mintIdentity('Emily Carter')
  assistant = await mintIdentity("Emily's assistant")
  greg = await mintIdentity('Greg Palmer')
  space = 'sp-demo-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6)
  const m0 = await openSpace(space, emily)                                    // founder only, epoch 0
  await api.create(m0)
  m = await admit(m0, emily, publicIdentity(assistant), { caps: ['read'] })    // epoch 1 — read · cannot post
  m = await admit(m, emily, publicIdentity(greg), { caps: ['read', 'submit'] }) // epoch 2
  await api.putMembers(space, m)
  $('epoch').textContent = 'epoch ' + m.epoch
  const link = location.origin + '/seat#' + btoa(JSON.stringify({ space, base: BASE, id: greg }))
  const a = $('greglink'); a.href = link; a.textContent = link
  presentDraft(); poll()
}

function presentDraft() {
  if (round >= SCRIPT.length) { $('draftArea').style.display = 'none'; return }
  $('agentNote').innerHTML = '<b>Assistant:</b> ' + SCRIPT[round].note
  $('draft').value = SCRIPT[round].draft
  $('draftArea').style.display = 'block'
  $('approve').disabled = false
}

$('approve').onclick = async () => {
  $('approve').disabled = true
  const content = $('draft').value.trim()
  if (!content) { $('approve').disabled = false; return }
  await api.submit(space, await makeCoSignedEntry(m, emily, assistant, { content })) // assistant drafted, Emily approves+signs
  round++
  $('draftArea').style.display = 'none'
  render()
}

async function poll() {
  try {
    const feed = await api.read(space)
    if (feed.entries.length !== lastLen) { lastLen = feed.entries.length; await render(feed) }
    const gregs = feed.entries.filter((x) => x.party === greg.id).length
    if (gregs > gregCount) { gregCount = gregs; if (round < SCRIPT.length) presentDraft() } // Greg replied → next draft
  } catch (e) { /* keep polling */ }
  setTimeout(poll, 2500)
}

async function render(feed) {
  feed = feed || await api.read(space)
  const t = $('thread')
  if (!feed.entries.length) { t.innerHTML = '<div class="empty">Nothing has crossed yet. Approve your first message.</div>'; return }
  const rows = await Promise.all(feed.entries.map(async (e) => {
    const v = await verifyEntry(m, e)
    const content = await openEntry(m, emily, e)
    const mine = e.party === emily.id
    const who = mine ? 'You (Emily)' : (m.members.find((x) => x.party === e.party)?.label || 'party')
    const drafted = e.draft ? " · drafted with Emily's assistant" : ''
    const attr = v.ok
      ? `<span class="ok">✓ ${e.draft ? 'authored by the assistant, approved &amp; signed by Emily' : 'signed by ' + esc(who)}</span>`
      : '<span class="bad">✗ signature did not verify</span>'
    return `<div class="msg ${mine ? 'me' : ''}"><div class="who2"><b>${esc(who)}</b>${drafted}</div>
      <div class="body">${esc(content || "(sealed to a key you don't hold)")}</div>
      <div class="attr">${attr}</div></div>`
  }))
  t.innerHTML = rows.join('')
  t.scrollTop = t.scrollHeight
}

$('src').onclick = (e) => { e.preventDefault(); window.open('https://github.com/kibitz-chat/witbitz-render', '_blank') }
setup().catch((err) => { $('thread').innerHTML = '<div class="empty">Setup error: ' + esc(err.message) + '</div>' })
