# The Asymmetric Bridge — a Witbitz demo

[![verify](https://github.com/kibitz-chat/witbitz-asymmetric-bridge/actions/workflows/verify.yml/badge.svg)](https://github.com/kibitz-chat/witbitz-asymmetric-bridge/actions/workflows/verify.yml) — the daily green check drives the **live** Bridge end to end.

**Live:** <https://witbitz-demo.pages.dev> · **the code that touches your data:** [witbitz-render](https://github.com/kibitz-chat/witbitz-render) · **verify:** <https://docs.witbitz.chat/docs/verify.md>

One side has an AI; the other has a link. A buyer (**Emily**) negotiates a supplier renewal with her assistant.
The assistant is admitted to the shared Bridge as **read · cannot post** — it can draft, it can never cross.
Every message that reaches the supplier (**Greg**) is one Emily *approved and signed*. Greg has no account and no
install — a link is his key — and everything he's asked to believe, he can check himself:

**What the live Bridge *adjudicates*** — a bad request gets a `4xx` from `api.witbitz.chat`, decided server-side. Each is paired in `live-e2e.mjs` with a **positive control** (the legitimate version *is* accepted), so "refused" is specific, not "the space broke":

| Claim | How the server refuses it |
|---|---|
| The assistant can't put anything in front of Greg | its solo submit → **`403`** (`read`, not `submit`, in the public membership) |
| …and it can't be *promoted* behind Emily's back | a PUT upgrading it — however signed (outsider, Greg, or the assistant itself) — → **`403`**; only a current `admit`-holder's signature re-caps |
| A space can't be founded in someone else's name | an unsigned/forged `create` → **`403`**; re-creating an existing id → **`409`** (first-create-wins) |
| A crossing can't be forged, tampered, or replayed | bad signature / altered body / non-member co-signer → **`400`**; replay across space or epoch → refused |
| A revoked admin can't reach back in | a record it pre-signed while it held `admit` → **`403`** after revocation; removing the last admit → **`403`**; a same-epoch race can't silently undo a revocation → **`403`** (first-write-wins) |
| Teardown is authorized + time-bound | a delete without a current admit-holder's **fresh** signature → **`403`** (the authorization expires; it rides in a header, not the URL) |

**What *you* verify yourself, client-side** — these hold *even if the server misbehaves*, because the platform never sees the plaintext. They are your own decryptions (`openEntry`), not something the Bridge adjudicates:

| Claim | How you check it locally |
|---|---|
| Every message is Emily's, co-authored by the assistant | the **two** signatures resolve against the public keys |
| The content is confidential — not the feed | the feed is public ciphertext; a body is **unreachable** without the epoch key you hold |
| Revocation protects the future, not the past | a revoked party still opens what it already held, but **never** the new epoch key — credible *because* it isn't absolute |
| A downgraded member is read-only, not blinded | stripped of `submit`, Greg is refused writes yet still **reads** new content (kept `read` + the new key) |

**The scope line, stated plainly:** every `4xx` in the first table is the *honest server choosing to enforce* — that
column assumes an **honest operator**. A dishonest one could accept a forged write, or serve one membership to Emily and
another to Greg (**equivocation**), and nothing in this suite would catch it. Defending against *that* is the
server-signed **checkpoint** layer parties pin + gossip — **designed, not yet built** (it's the next demo). The second
table is exactly what survives a dishonest server: your own decryptions, which the platform can neither see nor fake.

Every signature, seal, epoch key, and cap is **real** and keys never leave the browser. The negotiation copy — and the
prep room, and the assistant's reasoning — are **scripted** (see Scope).

## The files (this is the whole app — read it)

| File | What it is |
|---|---|
| [`bridgeClient.js`](./bridgeClient.js) | the browser Bridge client — mint identity, found/admit (party-side re-key), seal bodies + epoch keys, **sign + co-sign** entries, verify attribution, open by key. Its signatures verify against the server's own verifier (see the test). |
| [`prep.js`](./prep.js) | Emily's seat: draft → **edit** → approve → **co-signed** crossing |
| [`seat.js`](./seat.js) | Greg's link seat: read + verify every signature + open by his key + post; the `[check this]` widget |
| [`index.html`](./index.html) · [`seat.html`](./seat.html) · [`style.css`](./style.css) | the two seats |
| [`_headers`](./_headers) | the enforced CSP — `connect-src` is `self` + `api.witbitz.chat` **only** (the app's true egress) |
| [`live-e2e.mjs`](./live-e2e.mjs) | a runnable proof (`node live-e2e.mjs`) — drives the **live** Bridge end to end: every server refusal in the first table, plus revocation (pre-signed-transition, no-lockout), downgrade, first-write-wins concurrency, and the delete-token expiry edge. Each refusal is paired with a **positive control** so "refused" is specific, not "the space broke." Run daily by [CI](./.github/workflows/verify.yml). |
| [`server/`](./server) | **the Bridge server itself** (`bridgeHandler` + `bridgeLog` + `bridgeMembership` + `bridgeSpace`) and its **offline test suite** — so the deterministic proofs a live e2e *can't* show are runnable right here: `node --test server/*.test.mjs` (incl. the **atomic compare-and-set** [`server/bridgeHandler.test.mjs`](./server/bridgeHandler.test.mjs) — a lost race → `409`; the delete-token **expiry window**; and **equivocation detection** [`server/bridge.equivocation.test.mjs`](./server/bridge.equivocation.test.mjs) — a server forking the log to two parties, caught by comparing pinned checkpoints). |
| [`bridgeClient.test.mjs`](./bridgeClient.test.mjs) | interop: the browser client's signatures verified by the **server's own** verifier (`server/bridgeLog.mjs`). |

## Verify it yourself — offline, no network, no keys

```
node --test server/*.test.mjs bridgeClient.test.mjs   # 44 tests: attribution, membership authz, revocation, the
                                                       # pre-signed-transition attack, the ATOMIC compare-and-set (409),
                                                       # the delete-token expiry window, EQUIVOCATION detection, interop
node server/verify-guards.mjs                          # deletes each of the 16 security guards in turn and asserts the
                                                       # suite goes RED — a guard you can remove while tests stay green
                                                       # has no test. This is why the claims above aren't decorative.
```

The **live** proof (`node live-e2e.mjs`) can only show what an honest server *does*; these offline tests show what the code *is* — including the two things a client e2e structurally can't (atomicity of the epoch advance; that removing a guard breaks something).

> **One honest caveat.** [`server/`](./server) is the **source**. `live-e2e.mjs` shows the Bridge deployed at `api.witbitz.chat` behaving *identically* to it — strong **evidence**, but not **attestation**: nothing here cryptographically binds the running binary to this exact code. **Equivocation is now *detectable*:** a dishonest operator that serves Emily and Greg different logs is caught when they gossip the checkpoints they pinned — `verifyEquivocationProof` convicts the server by *its own two signatures* ([`server/bridge.equivocation.test.mjs`](./server/bridge.equivocation.test.mjs)). Still designed-not-built: binding the running binary to this source (attestation), the out-of-band gossip *transport*, and a public transparency log.

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
