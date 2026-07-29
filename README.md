# The Asymmetric Bridge — a Witbitz demo

**Live:** <https://witbitz-demo.pages.dev> · **the code that touches your data:** [witbitz-render](https://github.com/kibitz-chat/witbitz-render) · **verify:** <https://docs.witbitz.chat/docs/verify.md>

One side has an AI; the other has a link. A buyer (**Emily**) negotiates a supplier renewal with her assistant.
The assistant is admitted to the shared Bridge as **read · cannot post** — it can draft, it can never cross.
Every message that reaches the supplier (**Greg**) is one Emily *approved and signed*. Greg has no account and no
install — a link is his key — and everything he's asked to believe, he can check himself:

| Claim | How Greg checks it |
|---|---|
| The assistant could not put anything in front of him | the **public** membership record — `read`, not `submit` (the server refuses its submit `403`) |
| Every message is a commitment Emily signed | **two** signatures on the crossing, resolving against the public keys |
| Her private prep room never crossed | he holds no key to it — it's **unreachable**, not withheld by the UI |

The negotiation copy is scripted for the walkthrough. Every signature, seal, epoch key, and crossing is **real**,
run client-side against the live Bridge at `api.witbitz.chat/v1/bridge`. Keys never leave the browser.

## The files (this is the whole app — read it)

| File | What it is |
|---|---|
| [`bridgeClient.js`](./bridgeClient.js) | the browser Bridge client — mint identity, found/admit (party-side re-key), seal bodies + epoch keys, **sign + co-sign** entries, verify attribution, open by key. Its signatures verify against the server's own verifier (see the test). |
| [`prep.js`](./prep.js) | Emily's seat: draft → **edit** → approve → **co-signed** crossing |
| [`seat.js`](./seat.js) | Greg's link seat: read + verify every signature + open by his key + post; the `[check this]` widget |
| [`index.html`](./index.html) · [`seat.html`](./seat.html) · [`style.css`](./style.css) | the two seats |
| [`_headers`](./_headers) | the enforced CSP — `connect-src` is `self` + `api.witbitz.chat` **only** (the app's true egress) |
| [`live-e2e.mjs`](./live-e2e.mjs) | a runnable proof (`node live-e2e.mjs`) — drives the **live** Bridge end to end: co-signed crossing accepted, both signatures verified, the read-only assistant's solo submit refused `403`, a body **unreachable** without the key |

## What it does not prove — on the page, plainly

- Emily's ceiling was never transmitted, but the **shape** of her concessions still narrows where it sits.
  Encryption protects the channel, not the inference.
- The render decrypts the prep room to run the assistant. That it runs only the declared program is the
  **attested-tier** conditional — designed, not checkable today.
- Greg trusts that Emily reads what she approves. The runtime can enforce *that* she approved, never that it was wise.

## License
[Apache-2.0](./LICENSE).

---
Part of [Witbitz](https://witbitz.chat) · the Bridge protocol: <https://docs.witbitz.chat/docs/the-bridge.md>
