# Working in this repo

The gateways run from this checkout. `/Users/james/.hermes/hermes-agent` **is
production** — a broken intermediate state is live the moment a gateway
restarts. Edit in a worktree, never here.

```bash
git worktree add -b <branch> /Users/james/.hermes/worktrees/<name> deploy/juno-20260804
```

Tests run from the worktree using this checkout's venv:

```bash
cd /Users/james/.hermes/worktrees/<name>
PATH=/Users/james/.hermes/hermes-agent/venv/bin:$PATH \
  python -m pytest tests/plugins/test_juno_kite_slice_{a,b,c}.py \
  tests/plugins/test_juno_kite_trusted_principal.py -q --no-header -p no:cacheprovider
```

## Landing a branch — use the script

```bash
/Users/james/.hermes/scripts/land-worktree.sh <branch> [worktree-path]
```

It merges, removes the worktree and branch, restarts both gateways, stamps the
verifier, verifies, and only then pushes.

**Do not do this by hand.** Running `git merge` from inside the worktree prints
`Already up to date` and merges *nothing*, because the worktree is already on
that branch — and everything after it looks like it worked. That happened three
times in one day; once the worktree was then deleted while the shell stood
inside it, breaking every subsequent command. The script refuses when the merge
moves nothing, which is the check that would have caught all three.

Other things the script gets right because they were got wrong by hand:

- **Stamp `FIX` from the repo.** `~/.hermes` is not a git repo; running the
  `sed` from there made `git log` fail and wrote `FIX = ""`.
- **Verify before pushing, not after.** Both orders "pass"; only one of them
  tells you before the commit is public.
- **Never `rm -rf` a directory without looking inside it.** `.claude/worktrees/`
  in this repo holds *live subagent worktrees*. Deleting it as debris destroyed
  a running agent's uncommitted work.

## Two profiles, two configs

`~/.hermes` is Kite (default profile); `~/.hermes/profiles/juno` is Juno. They
have separate `config.yaml` files and separate gateways, and a change to one
does nothing for the other. Restart both:

```bash
hermes gateway restart && hermes --profile juno gateway restart
```

Neither is under version control. Config changes are only in the encrypted
backup, and a *quick* backup archives a state snapshot rather than the
`~/.hermes` tree — files under `hermes-agent` are only ever in a *full* backup.

## Before committing

A pre-commit hook blocks the household's real identifiers. Use synthetic test
data: Ofcom's reserved `07700 900xxx` range for phone numbers, invented
9-digit references, `example.com` addresses. The literals live outside the
repo in `~/.hermes/personal-identifiers.txt`.

The plan document is `~/.hermes/handoff/juno-document-release.md` — open
defects and next steps are §4.
