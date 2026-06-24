# Git hooks

Enable via:
```bash
git config core.hooksPath .githooks
```

## pre-push

Checks if `config.Version` matches the latest git tag when pushing to `main`.
Warns if it looks like you forgot to bump the version.

It's a warning, not a block — you can still push if you intentionally skipped the bump.
