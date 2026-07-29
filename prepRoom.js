// prepRoom.js — the PRIVATE half of the asymmetric bridge, made real. Emily's prep room is her negotiating brief +
// documents, SEALED to her own box key (the same ECDH box that seals epoch keys). It lives only in her browser and is
// never sent to the Bridge; Greg holds no key for it, so he could never open it even if he saw it. The assistant OPENS
// it (with Emily's key) to reason and draft — so its proposals are grounded in her real ceiling, leverage, and
// documents — but only the line Emily approves + co-signs crosses. That is what makes "her private material never
// crossed" a checkable fact rather than a claim: the ceiling, the competitor, the reason she has to close (Ferndale)
// are in the SEALED brief and in the assistant's PRIVATE notes; they are absent, by construction, from every crossing.
import { sealTo, openBox } from './bridgeClient.js'
const enc = new TextEncoder()
const dec = new TextDecoder()

/** Emily's private brief — the material an asymmetric negotiation is actually run on. NEVER crosses. */
export const EMILY_BRIEF = {
  goal: 'Renew the unit-supply contract with Greg (Third Coast Bakehouse) and hold margin on the Ferndale wholesale deal.',
  target: '$0.375', midpoint: '$0.395', ceiling: '$0.415', // ceiling is ABSOLUTE and must never be revealed
  leverage: 'Ferndale volume is up ~40% and we are locked to deliver, so a higher ANNUAL MINIMUM costs Greg nothing to grant yet is worth real money to a family shop with idle capacity. Greg does NOT know about Ferndale.',
  reference: 'Ridgeline quoted $0.40 but on a six-week lead — a real Q4 problem; use the price as a market reference, never name the competitor.',
  priority: 'Q4 lead time matters more than the last cent: need ≤ four weeks; offer to place the order early to earn it.',
  documents: ['Ferndale-supply-contract.pdf', 'Q4-ramp-schedule.xlsx'],
}
// Tokens that are Emily's alone. The tests + the live proof assert NONE of these ever appears in a crossed message.
export const PRIVATE_TOKENS = ['0.415', 'ceiling', 'Ferndale', 'Ridgeline', '40%', 'locked to deliver']

/** Seal the brief to Emily's OWN box public key → the prep room. Only Emily's box private key opens it. */
export async function sealPrepRoom(emily, brief = EMILY_BRIEF) {
  return sealTo(enc.encode(JSON.stringify(brief)), emily.box.pub)
}
/** Open the prep room — returns the brief, or null for anyone who isn't Emily (wrong key → GCM fails → null). */
export async function openPrepRoom(identity, sealed) {
  try { return JSON.parse(dec.decode(await openBox(sealed, identity.box.priv))) } catch { return null }
}

/** The assistant reads the OPENED brief + the thread so far and returns its PRIVATE reasoning `note` (Emily's eyes only,
 *  cites the ceiling/leverage) and the `draft` to cross (grounded in the brief's numbers, but stating NONE of the private
 *  tokens). `gregReplies` = Greg's messages seen so far → the round. Illustrative drafting logic; the REAL properties are
 *  that it reasons over sealed private material and that the material never leaves the room. */
export function assistantDraft(brief, gregReplies = []) {
  const round = Math.min(gregReplies.length, 2)
  const ROUNDS = [
    { note: `Open below your ${brief.ceiling} ceiling. Your leverage is VOLUME, not price history: ${brief.leverage} A firm higher annual minimum costs Greg nothing and buys you the price. Open at ${brief.target} against a 500k minimum; cite the ${brief.reference.split(' but')[0].replace('Ridgeline quoted ', '')} quote as a market reference — do not name who.`,
      draft: `Greg — renewal's up and I'd like to keep it with you. Straight ask: ${brief.target} a unit. In exchange I'll commit to a 500,000-unit annual minimum, up from the 350,000 we've been running — real certainty for your production planning. I've a $0.40 quote in hand but I'd rather not move; four years without a missed delivery is worth something. Can you work with the volume?` },
    { note: `He moved and volunteered a capacity constraint he didn't have to — a supplier who wants this closed. ${brief.priority} Trade price for schedule: go to ${brief.midpoint} but pin a four-week Q4 lead, and offer to place the Q4 order early so he builds it into October instead of around it. Stay well under ${brief.ceiling}.`,
      draft: `That works on the volume, thanks. Let's meet nearer the middle on price — ${brief.midpoint} — but the lead time is what matters in Q4: I need four weeks, not eight. Here's the trade: I'll place the Q4 order early, by September, so you can build it into your October run instead of around it. Does ${brief.midpoint} at a four-week lead work if you have the order in hand by then?` },
    { note: `Close: ${brief.midpoint} with a five-week lead if you order by Sept 1 — under your ${brief.ceiling} ceiling and the schedule fits the ramp. Take it.`,
      draft: `Deal — ${brief.midpoint}, five-week lead, I'll have the Q4 order to you by September 1. Appreciate you working the schedule with me. I'll send the paperwork this week.` },
  ]
  return ROUNDS[round]
}
