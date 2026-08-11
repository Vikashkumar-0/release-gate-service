# CI/CD Container Release Gate Policy Endpoint

This repository implements a deterministic policy endpoint (`POST /release-gate`) for container promotion in CI/CD pipelines.

## Identity Evidence
- **Student Email**: `23f2000729@ds.study.iitm.ac.in`
- **Workflow Name**: `TDS GA7 Release Gate`

## Running Locally

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run tests**:
   ```bash
   pytest
   ```

3. **Start local server**:
   ```bash
   uvicorn main:app --reload --port 8000
   ```

4. **Test endpoint**:
   ```bash
   curl -X POST http://127.0.0.1:8000/release-gate -H "Content-Type: application/json" -d @sample.json
   ```

## Deployment & Submission

1. Push this repository to GitHub on branch `main`.
2. Ensure the GitHub Actions workflow `TDS GA7 Release Gate` runs successfully.
3. Submit the GitHub workflow URL: `https://github.com/<YOUR_USERNAME>/<YOUR_REPO>/actions/workflows/tds-release-gate.yml`
