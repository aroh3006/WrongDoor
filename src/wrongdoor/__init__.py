"""WrongDoor: dynamic differential authorization tester.

Logs into a live API as several identities, has each create its own data,
then proves whether one identity can reach another's, producing a
reproducible HTTP request pair as evidence.

See docs/blueprint.md for the full architecture, roadmap, and rationale.
"""

__version__ = "0.0.0"
