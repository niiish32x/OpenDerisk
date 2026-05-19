"""Self-test for OAuth2 MOZI login flow.

Run with:
    uv run python scripts/test_mozi_oauth.py
"""

import asyncio
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages", "derisk-core", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages", "derisk-ext", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages", "derisk-serve", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages", "derisk-app", "src"))

PASSED = 0
FAILED = 0


def check(name: str, actual, expected):
    global PASSED, FAILED
    if actual == expected:
        PASSED += 1
        print(f"  PASS {name}: {actual}")
    else:
        FAILED += 1
        print(f"  FAIL {name}: got={actual!r}, expected={expected!r}")


# ---------------------------------------------------------------------------
# 1. Test MOZI user_info.json field mapping (based on real API response)
# ---------------------------------------------------------------------------
def test_userinfo_mapping():
    """Simulate the mapping logic from MoziProvider.fetch_userinfo fallback."""
    # Real MOZI user_info.json response (no email, no avatar)
    data = {
        "account": "nishenghao.nsh",
        "empId": "486200",
        "employeeCode": "486200",
        "lastName": "倪晟豪",
        "namespace": "alibaba",
        "nickNameCn": "越鸿",
        "openid": "32402c463b395c86b72f451fd239614c",
        "realmId": 10000,
        "realmName": "阿里巴巴集团",
    }
    result = {
        "id": str(
            data.get("empId")
            or data.get("employeeCode")
            or data.get("openid")
            or data.get("sub")
            or data.get("id")
            or ""
        ),
        "login": data.get("account", ""),
        "username": data.get("nickNameCn", ""),
        "name": data.get("lastName", ""),
        "email": (
            data.get("email")
            or data.get("mail")
            or data.get("email_address")
            or ""
        ),
        "avatar_url": data.get("avatar_url", data.get("avatar", "")),
        "avatar": data.get("avatar", ""),
        "picture": data.get("picture", ""),
    }
    check("mozi id=empId", result["id"], "486200")
    check("mozi login=account", result["login"], "nishenghao.nsh")
    check("mozi username=nickNameCn", result["username"], "越鸿")
    check("mozi name=lastName", result["name"], "倪晟豪")
    check("mozi email (not in API)", result["email"], "")


# ---------------------------------------------------------------------------
# 2. Test _claims_to_userinfo (JWT claim → user_info)
# ---------------------------------------------------------------------------
def test_claims_to_userinfo():
    from derisk_ext.plugin.auth.providers.mozi import _claims_to_userinfo

    claims = {
        "sub": "486200",
        "emp_id": "000001",
        "account": "nishenghao.nsh",
        "nickNameCn": "倪晟豪",
        "realName": "倪晟豪",
        "email": "nishenghao.nsh@alibaba-inc.com",
        "picture": "https://avatar.example.com/123.jpg",
    }
    info = _claims_to_userinfo(claims)
    check("claims id=sub", info["id"], "486200")
    check("claims login", info["login"], "nishenghao.nsh")
    check("claims username", info["username"], "倪晟豪")
    check("claims name", info["name"], "倪晟豪")
    check("claims email", info["email"], "nishenghao.nsh@alibaba-inc.com")
    check("claims avatar_url", info["avatar_url"], "https://avatar.example.com/123.jpg")

    # Without sub, fallback to emp_id
    claims2 = {"emp_id": "111", "name": "test", "email": "t@t.com"}
    info2 = _claims_to_userinfo(claims2)
    check("claims fallback emp_id", info2["id"], "111")


# ---------------------------------------------------------------------------
# 3. Test decode_jwt_payload
# ---------------------------------------------------------------------------
def test_decode_jwt():
    from derisk_ext.plugin.auth.providers.base import decode_jwt_payload
    import base64

    payload = json.dumps({"sub": "123", "email": "a@b.com"})
    encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    fake_jwt = f"header.{encoded}.signature"
    claims = decode_jwt_payload(fake_jwt)
    check("decode jwt sub", claims["sub"], "123")
    check("decode jwt email", claims["email"], "a@b.com")

    # Invalid JWT
    check("decode invalid", decode_jwt_payload("not.a.jwt"), None)
    check("decode empty", decode_jwt_payload(""), None)


# ---------------------------------------------------------------------------
# 4. Test auth_api token extraction logic
# ---------------------------------------------------------------------------
def test_token_extraction():
    """Test the logic used in auth_api.py to extract access_token/id_token."""

    def extract(token_data):
        if not token_data:
            return None, None
        access_token = (
            token_data.get("access_token")
            or (token_data.get("data") or {}).get("access_token")
            or (token_data.get("result") or {}).get("access_token")
        )
        id_token = (
            token_data.get("id_token")
            or (token_data.get("data") or {}).get("id_token")
            or (token_data.get("result") or {}).get("id_token")
        )
        return access_token, id_token

    at, it = extract({"access_token": "a", "id_token": "i"})
    check("extract flat at", at, "a")
    check("extract flat it", it, "i")

    at, it = extract({"data": {"access_token": "a2", "id_token": "i2"}})
    check("extract nested at", at, "a2")
    check("extract nested it", it, "i2")

    at, it = extract({"access_token": "a3"})
    check("extract no id_token", it, None)

    at, it = extract(None)
    check("extract None", at, None)


# ---------------------------------------------------------------------------
# 5. Integration test: start server, login, list users
# ---------------------------------------------------------------------------
async def test_server():
    import httpx

    base = "http://localhost:7777"
    async with httpx.AsyncClient() as client:
        # 5a. Login as admin
        resp = await client.post(
            f"{base}/api/v1/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        check("server login ok", resp.status_code, 200)
        data = resp.json()
        check("server login success", data.get("success"), True)
        token = data.get("data", {}).get("token")
        check("server login has token", bool(token), True)

        if not token:
            return

        headers = {"Authorization": f"Bearer {token}"}

        # 5b. List users
        resp = await client.get(f"{base}/api/v1/users", headers=headers)
        check("users api 200", resp.status_code, 200)
        users = resp.json()
        total = users.get("data", {}).get("total", 0)
        check("users api has data", total >= 2, True)

        # 5c. List RBAC users
        resp = await client.get(f"{base}/api/v1/permissions/users", headers=headers)
        check("permissions users 200", resp.status_code, 200)
        rbac = resp.json()
        rbac_total = rbac.get("data", {}).get("total", 0)
        check("permissions has data", rbac_total >= 2, True)

        # 5d. No duplicate users
        names = [u["name"] for u in users["data"]["list"]]
        dupes = [n for n in names if names.count(n) > 1]
        check("no duplicate users", len(dupes), 0)

        # 5e. OAuth status
        resp = await client.get(f"{base}/api/v1/auth/oauth/status")
        check("oauth status 200", resp.status_code, 200)
        oauth = resp.json()
        check("oauth enabled", oauth.get("enabled"), True)


def main():
    global PASSED, FAILED

    print("=" * 60)
    print("1. MOZI user_info.json field mapping")
    test_userinfo_mapping()

    print("=" * 60)
    print("2. _claims_to_userinfo")
    test_claims_to_userinfo()

    print("=" * 60)
    print("3. decode_jwt_payload")
    test_decode_jwt()

    print("=" * 60)
    print("4. Token extraction (auth_api logic)")
    test_token_extraction()

    print("=" * 60)
    print("5. Server integration tests")
    asyncio.run(test_server())

    print("=" * 60)
    print(f"Results: {PASSED} passed, {FAILED} failed, {PASSED + FAILED} total")

    if FAILED > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
