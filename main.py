import re
from typing import Any, Dict, List
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CI/CD Container Release Gate")


class ReleaseGateRequest(BaseModel):
    target: str
    event: str
    ref: str
    workflow: Dict[str, Any]
    image: Dict[str, Any]


@app.post("/release-gate")
def release_gate(payload: ReleaseGateRequest):
    violations: List[str] = []

    target = payload.target
    event = payload.event
    ref = payload.ref
    wf = payload.workflow or {}
    img = payload.image or {}

    # 1. EXCESS_PERMISSION
    # Permissions must be exactly least privilege for a release:
    # contents: read, packages: write, and id-token: none. No additional scopes may be present.
    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    actual_perms = wf.get("permissions")
    if not isinstance(actual_perms, dict) or actual_perms != expected_perms:
        violations.append("EXCESS_PERMISSION")

    # 2. UNSAFE_PR_TRIGGER
    # A pull request must use pull_request, never pull_request_target.
    trigger = wf.get("trigger")
    if trigger == "pull_request_target" or (
        event == "pull_request" and trigger != "pull_request"
    ):
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. TESTS_INCOMPLETE
    # Tests must pass, the whole matrix must finish, and failFast must be false.
    tests_passed = wf.get("testsPassed")
    matrix_complete = wf.get("matrixComplete")
    fail_fast = wf.get("failFast")

    if tests_passed is not True or matrix_complete is not True or fail_fast is not False:
        violations.append("TESTS_INCOMPLETE")

    # 4. MUTABLE_ACTION
    # Actions owned by actions may use a version tag.
    # Every third-party action must be pinned to a full 40-character lowercase hexadecimal commit SHA.
    actions = wf.get("actions", [])
    if isinstance(actions, list):
        sha_regex = re.compile(r"^[0-9a-f]{40}$")
        for action in actions:
            if isinstance(action, dict):
                owner = action.get("owner", "")
                action_ref = str(action.get("ref", ""))
                if owner != "actions":
                    if not sha_regex.match(action_ref):
                        violations.append("MUTABLE_ACTION")
                        break

    # 5. SINGLE_STAGE_IMAGE
    # The image must be multi-stage
    if img.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. ROOT_RUNTIME
    # run as non-root
    if img.get("runsAsRoot") is True:
        violations.append("ROOT_RUNTIME")

    # 7. SECRET_IN_LAYER
    # use either no build secret or a BuildKit secret mount
    secret_mode = img.get("secretMode")
    if secret_mode not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    # 8. CRITICAL_CVE
    # have zero critical vulnerabilities
    critical_cves = img.get("criticalVulnerabilities", 0)
    if critical_cves != 0:
        violations.append("CRITICAL_CVE")

    # 9. UNPINNED_IMAGE
    # and be referenced by digest
    if img.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10 & 11. Production requirements
    if target == "production":
        # Production additionally requires a push on refs/heads/main
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        # and an environmentApproval: true field on workflow.
        if wf.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if len(violations) == 0 else "block"

    return {"decision": decision, "violations": violations}
