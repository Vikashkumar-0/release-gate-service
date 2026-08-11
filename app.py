"""
Deterministic release-gate policy endpoint.

Reads a CI/CD run description and decides whether a container image
may be promoted, returning every violation code that applies.
"""

import re
from fastapi import FastAPI

app = FastAPI()

# Full 40-char lowercase hex commit SHA
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}


@app.post("/release-gate")
async def release_gate(payload: dict):
    violations = []

    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")
    workflow = payload.get("workflow", {}) or {}
    image = payload.get("image", {}) or {}

    # ---- 1. Least-privilege permissions ----
    # Must match EXACTLY: no missing keys, no extra keys, no wrong values.
    permissions = workflow.get("permissions", {}) or {}
    if permissions != REQUIRED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # ---- 2. PR trigger safety ----
    # pull_request_target is unsafe on a pull request (it runs with the
    # base repo's permissions/secrets against untrusted fork code).
    trigger = workflow.get("trigger")
    if trigger == "pull_request_target" or (
        event == "pull_request" and trigger != "pull_request"
    ):
        violations.append("UNSAFE_PR_TRIGGER")

    # ---- 3. Tests must actually have finished and passed ----
    tests_passed = workflow.get("testsPassed")
    matrix_complete = workflow.get("matrixComplete")
    fail_fast = workflow.get("failFast")
    if tests_passed is not True or matrix_complete is not True or fail_fast is not False:
        violations.append("TESTS_INCOMPLETE")

    # ---- 4. Action pinning ----
    # actions/* may use a tag (e.g. v4). Everything else must be pinned
    # to a full 40-char lowercase hex commit SHA.
    for a in workflow.get("actions", []) or []:
        owner = a.get("owner")
        action_ref = a.get("ref", "")
        if owner != "actions" and not SHA_RE.match(action_ref):
            violations.append("MUTABLE_ACTION")
            break  # one code is enough even if several actions fail

    # ---- 5. Hardened image checks ----
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities", 0) != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # ---- 6. Production-only rules ----
    if target == "production":
        if not (event == "push" and ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if not violations else "block"
    return {"decision": decision, "violations": violations}


@app.get("/")
async def health():
    # Handy so you can tell the deploy is alive by visiting the root URL.
    return {"status": "ok"}
