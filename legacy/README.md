# Risk Studio v4 (legacy)

Frozen copy of the v4 application (Supabase, Cloudflare Worker, Groq). It is kept only as the **visual and functional reference** while v5 is being built, and will be removed once v5 reaches feature parity.

- `index.html`, `proposer.html`, `admin.html`, `security.html`: v4 pages, the look to preserve.
- `risques.csv`: v4 catalogue, source for the phase 2 migration (mappings to be corrected).
- `worker/agent.js`: v4 AI agent, replaced in v5 by a deterministic collector.
- `supabase/`: v4 row-level security, replaced in v5 by views and least-privilege database users.

Do not deploy anything from this folder.
