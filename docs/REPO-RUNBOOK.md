# Repo runbook — foxyDesktopVPN (Tauri rewrite)

Manual steps only. CI never creates the repo (AC15): `.github/workflows/build.yml`
contains no `gh repo create` step and must never gain one — verify with
`grep -ri "repo.create" .github/` (expect empty).

`<ORG>/<REPO>` below is a placeholder (e.g. `you/foxyDesktopVPN` or
`you/foxy-tauri`). Substitute your real values; do not invent an org.

## 1. Create the public repo (once, from this worktree)

```sh
gh repo create <ORG>/<REPO> --public --source=. --remote=origin --push
```

If the remote already exists, point and push instead:

```sh
git remote add origin git@github.com:<ORG>/<REPO>.git  # or `gh repo ...` URL
git push -u origin main && git push --tags
```

## 2. Worktrees (this project uses one worktree per task)

```sh
git worktree list
git worktree add ../foxyDesktopVPN-wt-<name> -b impl/<name>
# when done: git worktree remove ../foxyDesktopVPN-wt-<name>
```

## 3. Updater signing key + secrets (Task 10 / AC14)

Generate once locally — the private key never enters the repo:

```sh
cargo tauri signer generate -w ~/.tauri/foxy.key
```

Then: paste the public key into `src-tauri/tauri.conf.json`
(`plugins.updater.pubkey`), replacing the `TODO(task10)` line, and replace
`<org>/<repo>` in `plugins.updater.endpoints` with the real repo path.

Store the private key as Actions secrets (repo Settings → Secrets → Actions):

- `TAURI_SIGNING_PRIVATE_KEY` — contents of `~/.tauri/foxy.key`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` — the password entered at keygen
  (empty string if none)

Without these secrets CI still builds green but emits unsigned bundles and the
`release` job refuses to publish (no `.sig` → no `latest.json`).

## 4. Release / update check (AC14)

```sh
git tag v0.2.0 && git push --tags   # CI builds, signs, publishes Release + latest.json
```

Manual verify: install vN, publish vN+1, confirm the app offers the update
(prompt or silent) without reinstall.

## 5. UI minimality re-audit (AC10/11/12)

`src/app.rs` must contain ONLY: sign-in button, server list (city/country +
Pick), Connect/Disconnect toggle + status line, error/status lines. No
split-tunnel/DNS screens, no dead buttons — every `on:click` handler sets a
status or error signal synchronously before any `await`.
