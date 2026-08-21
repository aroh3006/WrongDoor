"""WrongDoor: dynamic differential authorization tester.

Logs into a live API as several identities, has each create its own data,
then proves whether one identity can reach another's, producing a
reproducible HTTP request pair as evidence.

See README.md for usage and DECISIONS.md for the design rationale.
"""

__version__ = "0.1.0"
