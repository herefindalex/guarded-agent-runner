# GitHub Repository Settings Checklist

This checklist separates repository content from account-level and repository-level settings. Check an item only after observing it in GitHub. A workflow file in the repository does not prove that Actions, branch protection, or security settings are active.

## About metadata

Suggested description:

```text
Capability-scoped infrastructure action runner with exact human approval, resume revalidation, and audited execution.
```

Suggested topics:

```text
python
fastapi
react
agent-security
human-in-the-loop
policy-engine
infrastructure-automation
audit-log
```

Avoid topics such as `production-ready`, `autonomous-operations`, or `llm-agent`. They imply capabilities the current MVP deliberately does not claim.

## Repository presentation

- [ ] Confirm the About description matches the reviewed text above.
- [ ] Add the reviewed topics.
- [ ] Confirm README links render from the repository root.
- [ ] Add workflow badges only after hosted runs exist and the final repository URL is known.
- [ ] Confirm Mermaid diagrams render on GitHub.
- [ ] Add a license only after the owner selects one.
- [ ] Keep any public demo URL current or use local-run instructions instead.

## Actions

- [ ] Enable GitHub Actions.
- [ ] Run `CI` and inspect every job result.
- [ ] Run `Secret scan` and inspect the full-history Gitleaks result.
- [ ] Keep default workflow permissions read-only.
- [ ] Allow `packages: write` only for the container publication workflow.
- [ ] Confirm forked pull requests cannot access repository secrets.
- [ ] Review third-party Action versions before upgrading them.

Suggested required checks after their first successful hosted runs:

```text
CI / Python 3.12 tests and lint
CI / React production build
CI / Container build
Secret scan / Gitleaks repository history scan
```

## Branch protection

- [ ] Confirm the default branch.
- [ ] Require a pull request before merge.
- [ ] Require the checks listed above.
- [ ] Require branches to be up to date before merge.
- [ ] Block force pushes and branch deletion.
- [ ] Require conversation resolution.
- [ ] Decide whether administrator bypass is permitted.

## Security analysis

- [ ] Enable the dependency graph.
- [ ] Enable Dependabot alerts.
- [ ] Review Dependabot security updates before enabling automatic updates.
- [ ] Enable secret scanning where available.
- [ ] Enable push protection where available.
- [ ] Enable private vulnerability reporting.
- [ ] Keep any Gitleaks allowlist narrow, reviewed, and documented.

## Container publication

`release.yml` publishes to `ghcr.io/<owner>/<repository>` on `v*` tags or manual dispatch. Before the first run:

- [ ] Confirm the package visibility policy.
- [ ] Confirm `GITHUB_TOKEN` may write packages.
- [ ] Confirm generated image tags are correct.
- [ ] Inspect the SBOM and provenance attestation.
- [ ] Pull the immutable SHA tag and run `/health` locally.
- [ ] Do not treat image publication as production deployment.

Suggested verification after publication:

```bash
docker pull ghcr.io/<owner>/<repository>:sha-<commit>
docker run --rm -p 8000:8000 ghcr.io/<owner>/<repository>:sha-<commit>
curl --fail http://127.0.0.1:8000/health
```

Replace placeholders with the actual lower-case GitHub owner and repository.

## Release checklist

- [ ] Confirm CI and secret scan passed on the release commit.
- [ ] Confirm the capability and status documents match shipped behavior.
- [ ] Confirm release notes state `NO LLM CONNECTED`, `M1 FAKE TARGET ONLY`, and Paper mutation gates `NOT_RUN`.
- [ ] Confirm no screenshot or log contains private identifiers or credentials.
- [ ] Confirm the image starts as a non-root user and `/health` passes.
- [ ] Confirm there is no automatic infrastructure deployment.
- [ ] Record the tag, commit SHA, workflow URL, and image digest.

## Manual verification record

Record date, operator, link, and observed result beside completed items. Do not convert an unchecked item into a claim without evidence from the GitHub UI or API.

Related: [README](../README.md), [current status](STATUS.md), and [security guidance](SECURITY.md).
