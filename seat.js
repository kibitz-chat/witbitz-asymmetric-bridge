// seat.js — Greg's seat: a link, no account. He reads the shared thread, verifies every signature against the PUBLIC
// membership, opens what's sealed to the key his link carries, and posts directly. His identity (keys) lives only in
// the URL fragment — never sent to the server. The assistant is in the roster as read·cannot-post; every crossed
// message is one Emily approved and signed, and Greg can check that himself.
import { verifyEntry, openEntry, makeEntry, bridge } from './bridgeClient.js'
const $ = (id) => document.getElementById(id)
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]))

let cfg, api, me, m, lastLen = -1
try { cfg = JSON.parse(atob(location.hash.slice(1))) } catch { cfg = null }

async function start() {
  if (!cfg || !cfg.space || !cfg.id) { $('thread').innerHTML = '<div class="empty">This link is missing its Bridge details. Ask Emily to send it again.</div>'; return }
  me = cfg.id
  api = bridge(cfg.base || 'https://api.witbitz.chat/v1/bridge')
  m = await api.getMembers(cfg.space)
  renderRoster()
  poll()
  verifyPanel()
}

function labelOf(party) { return (m.members.find((x) => x.party === party)?.label) || 'party' }

function renderRoster() {
  const r = $('roster')
  r.innerHTML = m.members.map((mem) => {
    const isAsst = mem.caps.length === 1 && mem.caps[0] === 'read'
    const isMe = mem.party === me.id
    const capTxt = mem.caps.includes('submit') ? 'read · post' : 'read · cannot post'
    return `<div class="rmem ${isAsst ? 'assistant' : ''}">
      <span class="nm">${esc(mem.label || 'party')}${isMe ? ' (you)' : ''}</span>
      <span class="cap">${capTxt}</span>
      ${isAsst ? `<button class="check" data-asst="1">check</button>` : ''}
    </div>`
  }).join('')
  $('rosterNote').textContent = "Emily works with an AI assistant. It can read this thread and help her draft — it cannot post here. Every message from Emily's side is one she approved and signed."
  r.querySelector('[data-asst]')?.addEventListener('click', checkAssistant)
}

async function poll() {
  try {
    m = await api.getMembers(cfg.space)
    const feed = await api.read(cfg.space)
    if (feed.entries.length !== lastLen) { lastLen = feed.entries.length; await render(feed) }
  } catch (e) { /* keep polling */ }
  setTimeout(poll, 2500)
}

async function render(feed) {
  const t = $('thread')
  if (!feed.entries.length) { t.innerHTML = '<div class="empty">No messages yet.</div>'; return }
  const rows = await Promise.all(feed.entries.map(async (e, i) => {
    const v = await verifyEntry(m, e)
    const content = await openEntry(m, me, e)
    const mine = e.party === me.id
    const who = mine ? 'You (Greg)' : labelOf(e.party)
    const drafted = e.draft ? ` · drafted with ${esc(labelOf(e.draft.party))}` : ''
    const attr = v.ok
      ? `<span class="ok">✓ signed${e.draft ? ', approved by ' + esc(who === 'You (Greg)' ? who : labelOf(e.party)) : ' by ' + esc(who)}</span>`
      : '<span class="bad">✗ signature did not verify</span>'
    return `<div class="msg ${mine ? 'me' : ''}"><div class="who2"><b>${esc(who)}</b>${drafted}</div>
      <div class="body">${esc(content || "(sealed to a key you don't hold)")}</div>
      <div class="attr">${attr}<span class="check" data-i="${i}">check this</span></div></div>`
  }))
  t.innerHTML = rows.join('')
  t.querySelectorAll('[data-i]').forEach((el) => el.addEventListener('click', () => checkEntry(feed.entries[+el.dataset.i])))
  t.scrollTop = t.scrollHeight
}

$('send').onclick = async () => {
  const v = $('compose').value.trim()
  if (!v) return
  $('send').disabled = true
  try { await api.submit(cfg.space, await makeEntry(m, me, { content: v, actor: 'human' })); $('compose').value = ''; lastLen = -1; await poll() }
  catch (err) { alert('Could not post: ' + (err.message || err)) }
  $('send').disabled = false
}

// ── [check this] ────────────────────────────────────────────────────────────────────────────────────────────────────
function pop(title, rows) {
  $('popTitle').textContent = title
  $('popBody').innerHTML = rows.join('')
  $('pop').classList.add('on')
}
$('popClose').onclick = () => $('pop').classList.remove('on')
$('pop').addEventListener('click', (e) => { if (e.target === $('pop')) $('pop').classList.remove('on') })

async function checkAssistant() {
  const asst = m.members.find((x) => x.caps.length === 1 && x.caps[0] === 'read')
  pop("Emily's assistant — can it post?", [
    `<div class="rowline"><span class="mk ok">✓</span><div>Its capability in the <b>public</b> membership record is <b>[${asst.caps.join(', ')}]</b> — <b>read</b>, <b>not submit</b>. The server refuses any entry it tries to submit (<code>403 no_submit_cap</code>).</div></div>`,
    `<div class="rowline"><span class="mk"> </span><div class="mono">party ${esc(asst.party)}</div></div>`,
    `<div class="rowline"><span class="mk"> </span><div>This isn't a claim this page makes about itself — it's the record served by <code>${esc((cfg.base || '') + '/spaces/' + cfg.space + '/members')}</code>, which you can fetch yourself.</div></div>`,
  ])
}

async function checkEntry(entry) {
  const v = await verifyEntry(m, entry)
  const rows = []
  const approver = m.members.find((x) => x.party === entry.party)
  rows.push(`<div class="rowline"><span class="mk ${v.ok ? 'ok' : 'bad'}">${v.ok ? '✓' : '✗'}</span><div><b>Approved &amp; signed by ${esc(approver?.label || 'party')}</b> — signature verifies against their public key.<div class="mono">${esc(approver?.party || '')}</div></div></div>`)
  if (entry.draft) {
    const d = m.members.find((x) => x.party === entry.draft.party)
    rows.push(`<div class="rowline"><span class="mk ${v.ok ? 'ok' : 'bad'}">${v.ok ? '✓' : '✗'}</span><div><b>Authored by ${esc(d?.label || 'the assistant')}</b> — a second, independent signature over the same content, verifying against the assistant's public key.<div class="mono">${esc(d?.party || '')}</div></div></div>`)
  }
  rows.push(`<div class="rowline"><span class="mk"> </span><div>Both keys are in the public membership record. The content was decrypted here, in your browser, with the key your link carries.</div></div>`)
  pop('This message — two signatures', rows)
}

// ── verify panel: the app's real egress + build, off ground truth ───────────────────────────────────────────────────
async function verifyPanel() {
  $('vBuild').textContent = (document.querySelector('meta[name="build"]')?.content) || 'dev'
  try {
    const r = await fetch(location.pathname, { cache: 'no-store' })
    const csp = r.headers.get('content-security-policy') || ''
    const connect = (csp.match(/connect-src ([^;]+)/) || [])[1] || '(none)'
    $('vConnect').textContent = connect.trim()
  } catch { $('vConnect').textContent = '(could not read)' }
}

start().catch((err) => { $('thread').innerHTML = '<div class="empty">Error: ' + esc(err.message) + '</div>' })
