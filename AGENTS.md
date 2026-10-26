## graphify code graph

`graphify-out/` holds a local code graph built by [graphify](https://github.com/Graphify-Labs/graphify) from tree-sitter ASTs: no LLM, no network, no API cost. It is gitignored and rebuilt per machine; never commit it. `.graphifyignore`, when present, keeps evidence and generated folders out of the graph.

- When the `graphify` CLI is installed, run `graphify update .` before the first graph query of a session and again after finishing code changes. It is incremental and takes seconds to under a minute.
- Locate code through the graph first, then read only the lines it points to:
  - `graphify explain "<symbol>"`: callers, callees and imports, with file and line.
  - `graphify affected "<symbol>"`: what a change reaches, including the tests to run.
  - `graphify path "<A>" "<B>"`: how two parts connect.
  - `graphify query "<question>"`: keyword-seeded subgraph; noisy, use it only as a starting point.
- `INFERRED` edges are resolution guesses; confirm them in source. The graph is navigation only and never counts as evidence for builds, tests, releases or audits.
- If graphify is not installed, use normal search; do not install it as a side task.
