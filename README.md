# [Deep Researcher (FOSS)](https://serqai.com/deep-search.html)

# Demo of deep search web app: https://serqai.com/deep-search.html

A [repo](https://github.com/Antibody/deep-researcher-node) for Node.js web service for writing cited, outline-driven mini-review based on user's prompt. For each request it runs a multi-stage evidence pipeline: planning > search > fetching > open-access resolution > doc cards > claims > themed synthesis > polishing > expansions > final metrics.

No database required. All state is in memory with TTLs. 

You must bring your own OpenAI API for it to work, and optionally an Unpaywall email for better open-access (OA) resolution.

---

## Table of contents

* [Quick start](#quick-start)
* [API at a glance](#api-endpoints-at-a-glance)
* [Research pipeline](#research-pipeline)
* [Event stream (SSE)](#event-stream-sse)



---

## Quick start

### Prereqs

* Node.js 18+ (or 20+ recommended)
* An **OpenAI API key** (supplied per request via header)
* Optional: `UNPAYWALL_EMAIL` for better open-access lookups

### Install & run

```bash
git clone https://github.com/Antibody/deep-researcher-node.git
cd deep-researcher-node
npm i
node server.mjs
```


---

## API endpoints at a glance

### `POST /deep-research`

Kicks off a new “deep research” job and immediately acknowledges it so the UI stays responsive. The heavy lifting (planning, web search, fetching, OA resolution, claim extraction, synthesis, polishing) is done via ```runDeepResearchPipeline``` function.

### `GET /deep-research-FOSS-events?correlationId=…`

OPens a Server-Sent Events (SSE) stream for live progress. You’ll see named events like ready, search_results, fetched, writing_chunk, and a final done. If you connect late, the server replays the recent backlog so you don’t miss earlier steps. 15s heartbeats ensure proxies don’t idle the stream

### `GET /deep-research/status?correlationId=…`

Checks the current state of a job (e.g., queued, running, done, or error) and includes basic timing info. Useful for polling or debugging without attaching to SSE.



---

## Research pipeline

1. **Planner**
   Decomposes the prompt into a compact plan: `plan_title`, `subquestions[]`, `key_terms[]`, `success_criteria`.

2. **Outline designer (cached)**
   Produces 8–12 top-level headings. Cached for 1 hour per `correlationId` to avoid waste on retries.

3. **Query generator**
   Generates 14–22 high-yield queries using operators (`site:`, `filetype:pdf`, “review”, “meta-analysis”); biases toward PMC, PubMed, arXiv, and *.edu/*.gov.

4. **Web search**
   Uses OpenAI’s `web_search_preview` tool once per query; results are normalized (title/url/snippet/date).

5. **Selector (MMR + per-domain caps)**

   * Scores candidates with authority/freshness/relevance (+ OA boost)
   * Caps per domain to avoid monoculture
   * Embeds title+snippet and applies **MMR** (diversity) to choose a small, high-yield fetch set

6. **Fetch & enrich**

   * Fetch pages with timeouts, canonical URL & publish-date detection
   * PDF support (binary), HTML stripped to text
   * Skips junk/dynamic endpoints (e.g., social, Maps)

7. **Open-access resolution**

   * PubMed → PMC link detection
   * DOI lookup via Unpaywall and doi.org (HTML or PDF)
   * Upgrades abstract-only records to full-text when possible

8. **Doc cards & facts**

   * Builds structured “cards” (type, design, population, endpoints, **numerics** with effect sizes/CI/p, limitations)
   * Extracts salient fact lines (n, metrics, endpoints, doses)

9. **Claim extraction**

   * Produces 10–22 anchored claims with short quotes, numbers, and `source_idx` mapping
   * Fallbacks ensure claims even when strict JSON fails

10. **Theming**
    Buckets claims into pragmatic themes (Background, Methods/Theory, Evidence & Results, Comparisons, Implementation, Risks, Ethics).

11. **Synthesis**
   Synthesis produces a manuscript, originally driven by outline plan, with bracketed numeric citations [N]. In parallel, it emits an Evidence Matrix: a machine-readable pipeline control surface keyed by source index. The pipeline consumes this surface to compute citation coverage, derive per-source depth floors (mentions, words, quantified claims), schedule expansion units, and validate triangulation across paragraphs. The matrix is serialized in Markdown for telemetry (or user presentation).

12. **Polish for depth**
    Expands to meet **per-source floors** (mentions, words, quantified claims) while keeping section headings stable and avoiding citation spam.

13. **Capsules & triangulation**
    Generates 5–7 sentence **source capsules** for under-covered sources and comparison **triangulation** paragraphs (cite 2–3 sources per paragraph), then integrates them into the best-fit sections.

14. **Finalize & metrics**
    Ensures a “Sources” map block, and computes **citationCoverage** and **triangulationRatio** plus OA/abstract/blocks/docCard counts.

---

## Selection, fetching & OA resolution

* **Authority bias** toward `.gov`, `.edu`, major journals/standards; **freshness** based on detected dates
* **MMR** selection balances relevance to the centroid with diversity against already selected candidates
* **Per-domain caps** (default `3`) prevent vendor lock-in of evidence
* **OA preference** for PubMed Central and arXiv; **pivot** queries to OA when text is scarce
* **Unpaywall** requires `UNPAYWALL_EMAIL`; if omitted, OA success rate may drop

---

## Synthesis, polishing & expansions

1. **Initial synthesis**

   * Model writes the draft to the provided outline.
   * Citations use the numeric map `[n]` produced by source ordering.

2. **Evidence Matrix materialization (control surface)**

   * Each row aggregates machine-parsable fields for source `[n]`: `type`, `n/size`, `methods`, `key_results`, `limitations`.
   * The pipeline reads this surface (not the prose) to drive enforcement and scheduling.

3. **Coverage accounting**

   * Compute global and per-source stats from the draft:

     * `citationCoverage` (share of mapped sources cited at least once).
     * `triangulationRatio` (fraction of paragraphs citing ≥2 distinct sources).
     * Per-source tallies via sentence scanning: words, mentions, quantified sentences.
   * Compare against floors/goals (from `CFG.COVERAGE`):

     * `perSourceMinimumMentions`
     * `minWordsPerSource`
     * `minQuantClaimsPerSource`
     * Paragraph-level constraints: `minCitesPerParagraph`, `maxCitesPerSentence`.

4. **Brief generation (inputs for expansions)**

   * `buildSourceBriefs([n])` yields 4–6 bullet points per source with concrete numbers (methods → main results → harms → limitations).
   * Briefs are used as structured hints to increase factual density during expansion.

5. **Deficit detection & queueing**

   * Compute `coverageGoals` per source and identify deficits:

     * mention deficit, word deficit, quantified-claim deficit.
   * Rank sources by combined deficit score to form an **expansion queue**.

6. **Expansion unit generation**

   * **Source Capsules** (single-source deep paragraphs):

     * 5–7 sentences focused on one `[n]`.
     * Must include methods, dataset/sample size, effect sizes with CI/p, dose/route/duration when applicable.
     * Must cite only `[n]` at least twice.
   * **Triangulation Blocks** (multi-source comparison paragraphs):

     * Each paragraph contrasts 2–3 sources, explicitly calling agreements/disagreements and plausible causes (population, dataset, dose, follow-up, endpoints, bias).
     * Every sentence cites, and each paragraph cites ≥2 distinct sources.

7. **Structured integration**

   * `integrateExpansions` inserts Capsules and Triangulation Blocks under the best-fit outline sections without altering existing headings or removing prior text.
   * New sentences must satisfy citation constraints (`minCitesPerParagraph`, `maxCitesPerSentence`).

8. **Depth polish (goal-driven)**

   * `polishForDepth` revises/expands to meet per-source floors using:

     * Source briefs (for numeric/detail infusion).
     * Coverage goals (for targeted additions).
   * The pass is additive (no compression/removal) and preserves outline fidelity while raising quantitative density and triangulation.

9. **Final validation**

   * Recompute coverage metrics and ensure the control surface (Evidence Matrix) and the manuscript are consistent.
   * Append the numbered source map and persist stats in `meta` for telemetry/auditing.

---

## Event stream (SSE)

### Connection

* Endpoint: `/deep-research-FOSS-events?correlationId=...`
* Headers set for SSE: `Content-Type: text/event-stream`, `Cache-Control: no-cache, no-transform`, `Connection: keep-alive`, `X-Accel-Buffering: no`
* **Backlog**: up to the last 500 events per correlationId are replayed to late subscribers
* **Heartbeat**: `heartbeat` every 15s

### Events


* Lifecycle & control: `hello`, `heartbeat`, `ready`, `start`, `done`, `error`
* Planning: `plan_ready`, `outline_used`, `outline_final`
* Sub-Qs: `subq_start`, `subq_progress`, `subq_done`, `queries_ready`, `queries_seeded`
* Search/fetch: `search_start`, `search_progress`, `search_results`, `search_results_urls`, `fetch_start`, `fetched`, `crawl_progress`, `reranked`
* Writing: `synthesis_start`, `writing_started`, `writing_chunk`, `writing_progress`, `writing_done`
* Logging: `message`, `partial`, `debug`, `warn`, `error`
* Final stats: `final_stats`


---


