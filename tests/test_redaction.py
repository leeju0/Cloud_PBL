import unittest

from detector.redaction import redact_for_llm


class RedactionTests(unittest.TestCase):
    def test_masks_sensitive_values_but_keeps_detection_evidence(self):
        payload = {
            "objectRef": {"resource": "secrets", "name": "wallet"},
            "responseStatus": {"code": 403},
            "authorization": "Bearer very-secret-token",
            "token": "token-value",
            "requestObject": {"token": "token-value", "password": "pw"},
            "nested": [{"secretData": "do-not-send"}],
        }

        redacted = redact_for_llm(payload)

        self.assertEqual(redacted["objectRef"]["resource"], "secrets")
        self.assertEqual(redacted["responseStatus"]["code"], 403)
        self.assertEqual(redacted["authorization"], "[REDACTED]")
        self.assertEqual(redacted["token"], "[REDACTED]")
        self.assertNotIn("requestObject", redacted)
        self.assertEqual(redacted["nested"][0]["secretData"], "[REDACTED]")

    def test_does_not_mutate_input(self):
        payload = {"token": "original"}
        redact_for_llm(payload)
        self.assertEqual(payload["token"], "original")

    def test_masks_authorization_token_embedded_in_string(self):
        redacted = redact_for_llm({"userAgent": "Authorization: Bearer abc123"})

        self.assertEqual(redacted["userAgent"], "Authorization: Bearer [REDACTED]")


if __name__ == "__main__":
    unittest.main()
