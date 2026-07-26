# Repository agent instructions

## Commit before returning

After completing a user request, run the relevant validation and commit all
changes made for that request before sending the final response. Do not leave
agent-authored changes uncommitted.

Keep commits scoped to the requested work. Preserve unrelated or pre-existing
worktree changes, and do not include them in the commit. If a commit cannot be
created safely, explain the blocker in the final response.

Do not amend, rewrite, force-push, or otherwise alter existing history unless
the user explicitly requests it.

## Logging and privacy

Do not add logs containing information that Tailscale does not already log for
the equivalent operation. In particular, do not log IP addresses, DNS names,
node names, peer identities, packet endpoints, or similar identifiers.

Sensitive logging may be added temporarily for local debugging only. Remove all
such instrumentation, its tests, and its documentation before committing.
