# For maintainers

How nedctl is built, released and run as a platform service.

| Page | What it covers |
|---|---|
| [Azure DevOps](maintainers/azure-devops.md) | The CI, release and inventory pipelines; releasing a version; the AKS inventory and bastion mode |
| [Architecture](maintainers/architecture/README.md) | The draw.io diagrams of every flow and the code structure |
| [Fleet roadmap](maintainers/fleet-roadmap.md) | The early plan, written when the tool was called bankctl |

Changes reach `main` only by pull request with a green CI. A release is a
`vX.Y.Z` tag on `main`, which the release pipeline builds, verifies and
publishes. Bug fix: next patch (`v1.0.1`); new feature: next minor
(`v1.1.0`); a breaking change to a flag, setting or exit code: next major.
