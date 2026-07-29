# The Asymmetric Bridge — a Witbitz demo

[![verify](https://github.com/kibitz-chat/witbitz-asymmetric-bridge/actions/workflows/verify.yml/badge.svg)](https://github.com/kibitz-chat/witbitz-asymmetric-bridge/actions/workflows/verify.yml) — the daily green check drives the **live** Bridge end to end.

**Live:** <https://witbitz-demo.pages.dev> · **the code that touches your data:** [witbitz-render](https://github.com/kibitz-chat/witbitz-render) · **verify:** <https://docs.witbitz.chat/docs/verify.md>

One side has an AI; the other has a link. A buyer (**Emily**) negotiates a supplier renewal with her assistant.
The assistant is admitted to the shared Bridge as **read · cannot post** — it can draft, it can never cross.
Every message that reaches the supplier (**Greg**) is one Emily *approved and signed*. Greg has no account and no
install — a link is his key — and everything he's asked to believe, he can check himself:

| Claim | How you check it (all exercised by `live-e2e.mjs`) |
|---|---|
| The assistant can't put anything in front of Greg | `read`, not `submit` in the **public** membership; its solo submit is refused **`403`** |
| …and it can't be *promoted* behind Emily's back | an outsider — or Greg — PUTting a membership that upgrades the assistant to `submit` is refused **`403`**; only a **current `admit`-holder's signature** re-caps anyone (the server verifies it, independently) |
| Every message is Emily's, co-authored by the assistant | **two** signatures on the crossing, resolving against the public keys |
| The signatures **bind** the content | altering a crossed message's body is refused **`400`** — present ≠ binding |
| The drafter attribution isn't decorative | a co-signature naming a **non-member** is refused **`400`** |
| The content is confidential — not the feed | the feed is public ciphertext; a body is **unreachable** without the key |

Every signature, seal, epoch key, cap, and integrity check is **real**, run client-side against the live Bridge at
`api.witbitz.chat/v1/bridge`; keys never leave the browser. The negotiation copy — and the prep room, and the
assistant's reasoning — are **scripted** (see Scope).

## The files (this is the whole app — read it)

| File | What it is |
|---|---|
| [`bridgeClient.js`](./bridgeClient.js) | the browser Bridge client — mint identity, found/admit (party-side re-key), seal bodies + epoch keys, **sign + co-sign** entries, verify attribution, open by key. Its signatures verify against the server's own verifier (see the test). |
| [`prep.js`](./prep.js) | Emily's seat: draft → **edit** → approve → **co-signed** crossing |
| [`seat.js`](./seat.js) | Greg's link seat: read + verify every signature + open by his key + post; the `[check this]` widget |
| [`index.html`](./index.html) · [`seat.html`](./seat.html) · [`style.css`](./style.css) | the two seats |
| [`_headers`](./_headers) | the enforced CSP — `connect-src` is `self` + `api.witbitz.chat` **only** (the app's true egress) |
| [`live-e2e.mjs`](./live-e2e.mjs) | a runnable proof (`node live-e2e.mjs`) — drives the **live** Bridge end to end: co-signed crossing accepted + verified; assistant solo submit **`403`**; **tampered body `400`**; **non-member drafter `400`**; **the "upgrade the assistant" attack `403`** (however signed — outsider, Greg, or the assistant itself); replay across space/epoch **refused**; a body unreachable without the key. Each refusal is paired with a **positive control** (a fresh entry at the new epoch / native to B *is* accepted) so "refused" is specific, not "the space broke." Teardown is a **signed** delete; a hiccup is a warning, never a red badge. Run daily by [CI](./.github/workflows/verify.yml). |

## Scope — what this demo implements

The **crossing**: real signatures, caps, and content-integrity, live against the Bridge. Emily's **prep room**
(a sealed Space with her brief and documents) and the assistant's **model turn** are **scripted** — not built in
this repo. So "her private material never crossed" is true because there's nothing here to cross; what's exercised
is the crossing itself. The Bridge is the novel half — and the real one.

## What it does not prove — plainly

- Emily's ceiling was never transmitted, but the **shape** of her concessions still narrows where it sits.
  Encryption protects the channel, not the inference.
- In the *full* system the render decrypts the prep room to run the assistant — that it runs only the declared
  program is the **attested-tier** conditional (designed, not checkable today). This demo has **no such render**;
  the model turn is scripted.
- Greg trusts that Emily reads what she approves. The runtime can enforce *that* she approved, never that it was wise.

## License
[Apache-2.0](./LICENSE).

---
Part of [Witbitz](https://witbitz.chat) · the Bridge protocol: <https://docs.witbitz.chat/docs/the-bridge.md>
