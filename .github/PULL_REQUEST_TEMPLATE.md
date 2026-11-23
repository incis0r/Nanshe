## What and why

## How it was tested

- [ ] Unit tests: `scripts/dev.sh cargo test --workspace --features nanshe-cli/llm`
- [ ] Linux end-to-end: `scripts/dev.sh sh scripts/e2e.sh`
- [ ] Windows (only if Windows-specific code changed; dedicated test host):
- [ ] New checks were confirmed to fail when the code is broken on purpose

## Checklist

- [ ] One topic; commits make sense on their own
- [ ] Texts for humans go through `tr!`/`trf!`; `kb/` changes mirrored in `kb/en/`
- [ ] Documentation and `CHANGELOG.md` updated where behaviour changed
- [ ] No real scan data, credentials or keys in the change
