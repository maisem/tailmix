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
