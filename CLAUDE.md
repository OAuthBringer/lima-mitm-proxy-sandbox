# Project conventions

## No hard-coded paths in docs or code

Never write machine-specific or checkout-specific paths (e.g. `~/dev/<repo>`, `/Users/<name>/...`,
`/opt/homebrew/...`) in documentation, comments, scripts, or config. Renaming or moving the
checkout must never require an edit.

- Scripts resolve their own location (`ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"`) and derive everything from it.
- Docs use commands relative to the checkout root (`./reset.sh`, `source env.sh`), `make` targets, or placeholders such as `<checkout>`.
- Tool locations come from `PATH` or environment variables (`LIMA_HOME`), not literal install paths.
- Paths inside the VM (`/var/lib/egress`, `/etc/egress`, ...) are part of the guest's fixed layout, not host paths, and are fine to document.
- Lima's own cache location is a Lima default; refer to it generically instead of spelling it out.

## Documentation

- All documentation lives in `docs/`, with capitalized file names (`docs/TESTING.md`, not `docs/testing.md`).
- The root `README.md` is the only other Markdown file allowed. Keep it to what the project is and how to use it; link to `docs/` for detail such as testing.
- `.gitignore` enforces this: all `*.md` is ignored except `/README.md` and `/docs/**/*.md`. Do not add exceptions or force-add other Markdown files.
