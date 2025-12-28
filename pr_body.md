Summary

- Adds a workflow step to run `check_repos_status.py` before `pipeline.py` to detect and remove missing repositories from `detected_repos.json`.
- Adds `PyYAML` to `requirements.txt` for local/CI YAML validation.

Why

Ensures the pipeline operates on currently available repositories and prevents reporting on repos that were deleted or moved. Also provides a YAML parser for workflow checks and linting.

Files changed

- .github/workflows/daily-scan.yml
- requirements.txt

Testing

- CI will run on this PR; the `scan` job will exercise the new step. Locally you can activate the venv and run `pip install -r requirements.txt` then test the script.

Notes

- Workflow uses GitHub Secrets (e.g., `SCAN_TOKEN`). Do not commit secrets into repo. `.env.local` is gitignored for local use only.
