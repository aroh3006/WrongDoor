# WrongDoor packaged as a GitHub Action.
#
# Installs the published CLI from PyPI (available after the Phase 7 release).
# Identity secrets (e.g. ALICE_PW) are passed through the job's `env:`.
# Until the PyPI release, the repo's own CI dogfoods by installing from source
# (see .github/workflows/ci.yml) rather than via this action.
FROM python:3.12-slim
RUN pip install --no-cache-dir wrongdoor
ENTRYPOINT ["wrongdoor"]
