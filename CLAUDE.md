# WrongDoor — Project Instructions

Read docs/blueprint.md first — it is the full architecture, roadmap,
and design rationale for this project. Follow it exactly. Do not
deviate from its tech stack, phase order, or architecture decisions
without discussing it with me first.

## Workflow rules
- Work in small, complete units: one function or module at a time.
- Write tests for each unit before moving to the next.
- After each unit is done AND passing tests, commit with a clear
  message and push to GitHub. Don't batch multiple commits before pushing.
- Follow the blueprint's roadmap (§14) phase order — don't skip ahead.

## Files I must personally understand line-by-line (§15/§18 of blueprint)
Explain your reasoning inline when drafting these. I will read every
line before accepting:
- engine/verdict.py, engine/diff.py, engine/seeder.py,
  engine/ledger.py, engine/planner.py, safety/guard.py

## Git commit conventions
Do not include a `Co-Authored-By: Claude` trailer in any commit message.

## Everything else
Draft more freely, but I'll still review it.