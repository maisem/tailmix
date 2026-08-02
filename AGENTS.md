# Repository agent instructions

## Commit before returning

After completing a user request, run `make check` and commit all changes made
for that request before sending the final response. Do not leave agent-authored
changes uncommitted.

Keep commits scoped to the requested work. Preserve unrelated or pre-existing
worktree changes, and do not include them in the commit. If a commit cannot be
created safely, explain the blocker in the final response.

Do not amend, rewrite, force-push, or otherwise alter existing history unless
the user explicitly requests it.

Follow the [Tailscale commit message guidelines](https://github.com/tailscale/tailscale/blob/main/docs/commit-messages.md)
for every commit.

## Logging and privacy

Do not add logs containing information that Tailscale does not already log for
the equivalent operation. In particular, do not log IP addresses, DNS names,
node names, peer identities, packet endpoints, or similar identifiers.

Sensitive logging may be added temporarily for local debugging only. Remove all
such instrumentation, its tests, and its documentation before committing.

## Upstream forks

Keep the first commit that imports an upstream library as an unmodified
snapshot of the selected upstream revision. Preserve upstream copyright
headers and include its license. Do not mix tailmix adaptations, generated
metadata, or unrelated changes into that import commit.

Add tailmix-specific changes only in follow-up commits. Apply the same split
when refreshing a fork: first commit the clean upstream update, then commit the
adaptations needed to reconcile tailmix.

Every fork directory must contain a README that links to the upstream
repository and exact commit, identifies the upstream module version and source
path when applicable, explains why the fork exists, and summarizes the
behavioral differences carried by tailmix. Keep a machine-readable `UPSTREAM`
record beside the README.
