"""针对已修复安全与业务逻辑问题的隔离回归测试。"""
import math
import sqlite3
import tempfile
import unittest
from pathlib import Path

import app as cat_app
from init_db import SCHEMA


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db_path = cat_app.DB_PATH
        cat_app.DB_PATH = Path(self.temp_dir.name) / "test.db"

        conn = sqlite3.connect(cat_app.DB_PATH)
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO users (id, username, password_hash, display_name) VALUES (1, 'tester', 'unused', 'Tester')"
        )
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES ('test-token', 1, '2999-01-01T00:00:00')"
        )
        conn.commit()
        conn.close()

        cat_app.app.config.update(TESTING=True)
        self.client = cat_app.app.test_client()
        self.auth = {"Authorization": "Bearer test-token"}

    def tearDown(self):
        cat_app.DB_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def _login(self, username, password):
        response = self.client.post(
            "/api/auth/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200)
        return {"Authorization": "Bearer " + response.get_json()["token"]}

    def test_private_project_files_are_not_served(self):
        for path in ("/diary.db", "/app.py", "/certs/key.pem"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)
        image_response = self.client.get("/images/cat/cat-happy.png")
        try:
            self.assertEqual(image_response.status_code, 200)
        finally:
            image_response.close()

    def test_bucket_done_requires_json_boolean(self):
        conn = sqlite3.connect(cat_app.DB_PATH)
        conn.execute(
            "INSERT INTO buckets (id, title, category, cat_key, created_at) VALUES ('b1', 'test', 'food', 'fish', '2026-01-01')"
        )
        conn.commit()
        conn.close()
        response = self.client.patch("/api/buckets/b1", json={"done": "false"}, headers=self.auth)
        self.assertEqual(response.status_code, 400)

    def test_non_string_json_fields_return_400_instead_of_500(self):
        cases = (
            ("/api/auth/login", {"username": 123, "password": "x"}, {}),
            ("/api/auth/login", {"username": "tester", "password": 123}, {}),
            ("/api/buckets", {"title": {"bad": True}, "category": "food"}, self.auth),
            ("/api/scores", {"text": ["bad"]}, self.auth),
            ("/api/together", {"start_date": 20260831, "anniversaries": []}, self.auth),
        )
        for path, payload, headers in cases:
            with self.subTest(path=path):
                response = self.client.post(path, json=payload, headers=headers) if path != "/api/together" else self.client.put(path, json=payload, headers=headers)
                self.assertEqual(response.status_code, 400)

    def test_authorization_requires_bearer_scheme(self):
        self.assertEqual(
            self.client.get("/api/auth/me", headers={"Authorization": "Basic test-token"}).status_code,
            401,
        )

    def test_non_finite_numbers_are_rejected(self):
        cases = (
            ("/api/scores", {"text": "bad", "score": math.nan}),
            ("/api/pet/work", {"hours": math.inf}),
            ("/api/pet/study", {"hours": math.nan}),
        )
        for path, payload in cases:
            with self.subTest(path=path):
                response = self.client.post(path, json=payload, headers=self.auth)
                self.assertEqual(response.status_code, 400)

    def test_study_uses_constant_experience_per_level(self):
        conn = sqlite3.connect(cat_app.DB_PATH)
        conn.execute("UPDATE pet_state SET level=2, exp=90, mood=50, last_decay_at=datetime('now', 'localtime') WHERE id=1")
        conn.commit()
        conn.close()
        response = self.client.post("/api/pet/study", json={"hours": 2}, headers=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["queued"])
        conn = sqlite3.connect(cat_app.DB_PATH)
        conn.execute("UPDATE pet_actions SET available_at='2000-01-01T00:00:00' WHERE status='pending'")
        conn.commit()
        conn.close()
        settled = self.client.post("/api/pet/settle", headers=self.auth)
        self.assertEqual(settled.status_code, 200)
        self.assertEqual(settled.get_json()["new_level"], 3)
        conn = sqlite3.connect(cat_app.DB_PATH)
        level, exp = conn.execute(
            "SELECT level, exp FROM pair_pet_state WHERE pair_id=(SELECT pair_id FROM users WHERE id=1)"
        ).fetchone()
        conn.close()
        self.assertEqual((level, exp), (3, 10))

    def test_pet_reports_actual_clamped_delta(self):
        conn = sqlite3.connect(cat_app.DB_PATH)
        conn.execute("UPDATE pet_state SET mood=100, last_decay_at=datetime('now', 'localtime') WHERE id=1")
        conn.commit()
        conn.close()
        response = self.client.post("/api/pet/pet", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["delta"]["mood"], 0)

    def test_new_pet_does_not_decay_immediately_due_to_utc_offset(self):
        response = self.client.get("/api/pet", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        pet = response.get_json()
        self.assertEqual((pet["hunger"], pet["mood"], pet["energy"]), (50, 50, 50))

    def test_pair_registration_is_atomic_and_data_is_isolated(self):
        payload = {
            "accounts": [
                {"username": "alpha", "displayName": "Alpha", "password": "alpha-pass-123"},
                {"username": "beta", "displayName": "Beta", "password": "beta-pass-123"},
            ]
        }
        response = self.client.post("/api/auth/register-pair", json=payload)
        self.assertEqual(response.status_code, 201)

        alpha_auth = self._login("alpha", "alpha-pass-123")
        beta_auth = self._login("beta", "beta-pass-123")
        created = self.client.post(
            "/api/buckets",
            json={"title": "pair only", "category": "play", "catKey": "star"},
            headers=alpha_auth,
        )
        self.assertEqual(created.status_code, 200)
        beta_items = self.client.get("/api/buckets", headers=beta_auth).get_json()["buckets"]
        legacy_items = self.client.get("/api/buckets", headers=self.auth).get_json()["buckets"]
        self.assertEqual([item["title"] for item in beta_items], ["pair only"])
        self.assertEqual(legacy_items, [])
        bucket_id = created.get_json()["bucket"]["id"]
        self.assertEqual(
            self.client.patch(
                f"/api/buckets/{bucket_id}", json={"done": True}, headers=self.auth
            ).status_code,
            404,
        )

        self.assertEqual(
            self.client.post(
                "/api/scores",
                json={"text": "shared score", "type": "plus", "score": 2},
                headers=alpha_auth,
            ).status_code,
            200,
        )
        self.assertEqual(len(self.client.get("/api/scores", headers=beta_auth).get_json()["scores"]), 1)
        self.assertEqual(self.client.get("/api/scores", headers=self.auth).get_json()["scores"], [])

        self.assertEqual(
            self.client.post(
                "/api/guestbook", json={"content": "pair message"}, headers=alpha_auth
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.get("/api/guestbook", headers=beta_auth).get_json()["messages"][0]["content"],
            "pair message",
        )
        self.assertEqual(self.client.get("/api/guestbook", headers=self.auth).get_json()["messages"], [])

        together = {"start_date": "2026-01-02", "anniversaries": []}
        self.assertEqual(
            self.client.put("/api/together", json=together, headers=alpha_auth).status_code,
            200,
        )
        self.assertEqual(
            self.client.get("/api/together", headers=beta_auth).get_json()["start_date"],
            "2026-01-02",
        )
        self.assertIsNone(self.client.get("/api/together", headers=self.auth).get_json()["start_date"])

        self.assertEqual(self.client.post("/api/pet/pet", headers=alpha_auth).status_code, 200)
        self.assertEqual(self.client.get("/api/pet", headers=beta_auth).get_json()["mood"], 51)
        self.assertEqual(self.client.get("/api/pet", headers=self.auth).get_json()["mood"], 50)
        conn = sqlite3.connect(cat_app.DB_PATH)
        conn.execute(
            "UPDATE pair_pet_state SET gold=100 WHERE pair_id=(SELECT pair_id FROM users WHERE username='alpha')"
        )
        conn.commit()
        conn.close()
        self.assertEqual(
            self.client.post(
                "/api/pet/buy",
                json={"item_key": "cat-treat", "quantity": 2},
                headers=alpha_auth,
            ).status_code,
            200,
        )
        beta_inventory = self.client.get("/api/pet/inventory", headers=beta_auth).get_json()["items"]
        treat = next(item for item in beta_inventory if item["key"] == "cat-treat")
        self.assertEqual(treat["quantity"], 2)
        visible_users = self.client.get("/api/presence", headers=beta_auth).get_json()["users"]
        self.assertEqual({user["username"] for user in visible_users}, {"alpha", "beta"})

        duplicate_payload = {
            "accounts": [
                {"username": "alpha", "password": "another-pass-123"},
                {"username": "gamma", "password": "gamma-pass-123"},
            ]
        }
        duplicate = self.client.post("/api/auth/register-pair", json=duplicate_payload)
        self.assertEqual(duplicate.status_code, 409)
        conn = sqlite3.connect(cat_app.DB_PATH)
        gamma_count = conn.execute("SELECT COUNT(*) FROM users WHERE username='gamma'").fetchone()[0]
        conn.close()
        self.assertEqual(gamma_count, 0)


if __name__ == "__main__":
    unittest.main()
