// prep.js — Emily's seat: the private prep room. Founds the Bridge, mints the parties, admits the assistant as
// read-only, and crosses only what Emily approves + signs (a CO-SIGNED entry). All keys stay in this browser.
import { mintIdentity, publicIdentity, openSpace, admit, makeCoSignedEntry, verifyEntry, openEntry, bridge } from './bridgeClient.js'
import { EMILY_BRIEF, sealPrepRoom, openPrepRoom, assistantDraft } from './prepRoom.js'
const BASE = 'https://api.witbitz.chat/v1/bridge'
const api = bridge(BASE)
const $ = (id) => document.getElementById(id)
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]))

// Emily's prep room renders here — HER eyes only. It is sealed to her key (below) and never sent to the Bridge.
const ROUNDS = 3
function renderBrief(b) {
  return `<div style="font-size:12px;color:#0a7;font-weight:600;margin-bottom:8px">🔒 Sealed to Emily · never crosses the Bridge</div>
    <p><b>Goal.</b> ${esc(b.goal)}</p>
    <p><b>Price.</b> target ${esc(b.target)} · midpoint ${esc(b.midpoint)} · <span style="color:#c00">ceiling ${esc(b.ceiling)} — never reveal</span></p>
    <p><b>Leverage.</b> ${esc(b.leverage)}</p>
    <p><b>Reference.</b> ${esc(b.reference)}</p>
    <p><b>Priority.</b> ${esc(b.priority)}</p>
    <p><b>Documents.</b> ${b.documents.map(esc).join(' · ')}</p>`
}

let emily, assistant, greg, m, space, sealedBrief, round = 0, gregCount = 0, lastLen = -1

async function setup() {
  emily = await mintIdentity('Emily Carter')
  sealedBrief = await sealPrepRoom(emily)             // Emily's brief, sealed to HER box key — it never leaves this browser
  $('brief').innerHTML = renderBrief(EMILY_BRIEF)
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

async function presentDraft() {
  if (round >= ROUNDS) { $('draftArea').style.display = 'none'; return }
  const brief = await openPrepRoom(emily, sealedBrief)   // the assistant OPENS the sealed prep room to reason over it
  const { note, draft } = assistantDraft(brief, Array(round).fill(0))
  $('agentNote').innerHTML = '<b>Assistant (private — never crosses):</b> ' + note
  $('draft').value = draft
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
    if (gregs > gregCount) { gregCount = gregs; if (round < ROUNDS) presentDraft() } // Greg replied → next draft
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
