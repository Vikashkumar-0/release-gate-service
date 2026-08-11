from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_valid_preview_release():
    payload = {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none",
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {
                    "owner": "thirdparty",
                    "name": "setup",
                    "ref": "a1b2c3d4e5f6071829304152637485960718293a",
                },
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "buildkit",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }
    response = client.post("/release-gate", json=payload)
    assert response.status_code == 200
    assert response.json() == {"decision": "promote", "violations": []}


def test_valid_production_release():
    payload = {
        "target": "production",
        "event": "push",
        "ref": "refs/heads/main",
        "workflow": {
            "trigger": "push",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none",
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}],
            "environmentApproval": True,
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }
    response = client.post("/release-gate", json=payload)
    assert response.status_code == 200
    assert response.json() == {"decision": "promote", "violations": []}


def test_individual_violations():
    # 1. Excess Permission
    p = get_valid_payload()
    p["workflow"]["permissions"]["admin"] = "write"
    res = client.post("/release-gate", json=p).json()
    assert "EXCESS_PERMISSION" in res["violations"]

    # 2. Unsafe PR trigger
    p = get_valid_payload()
    p["workflow"]["trigger"] = "pull_request_target"
    res = client.post("/release-gate", json=p).json()
    assert "UNSAFE_PR_TRIGGER" in res["violations"]

    # 3. Mutable Action
    p = get_valid_payload()
    p["workflow"]["actions"].append(
        {"owner": "someone", "name": "action", "ref": "v1"}
    )
    res = client.post("/release-gate", json=p).json()
    assert "MUTABLE_ACTION" in res["violations"]

    # 4. Secret in layer
    p = get_valid_payload()
    p["image"]["secretMode"] = "arg"
    res = client.post("/release-gate", json=p).json()
    assert "SECRET_IN_LAYER" in res["violations"]


def get_valid_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature-1",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none",
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }
