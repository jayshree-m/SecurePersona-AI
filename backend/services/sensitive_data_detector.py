import re


class SensitiveDataDetector:
    def __init__(self):
        self.patterns = {
            "Email": re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
            ),
            "Phone Number": re.compile(
                r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"
            ),
            "Aadhaar Number": re.compile(
                r"(?<!\d)(?:\d{4}[\s-]){2}\d{4}(?!\d)|(?<!\d)\d{12}(?!\d)"
            ),
            "PAN": re.compile(
                r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", re.IGNORECASE
            ),
            "UPI ID": re.compile(
                r"\b[a-zA-Z0-9._-]+@(?:oksbi|okaxis|okhdfcbank|okicici|ybl|ibl|axl|upi|paytm|phonepe|gpay)\b",
                re.IGNORECASE
            ),
            "Credit/Debit Card": re.compile(
                r"(?<!\d)(?:\d{4}[\s-]?){3}\d{4}(?!\d)"
            ),
            "Password": re.compile(
                r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+",
                re.IGNORECASE
            ),
            "API Key": re.compile(
                r"\b(?:api[_\s-]?key|secret[_\s-]?key)\s*[:=]\s*[A-Za-z0-9_\-]{8,}",
                re.IGNORECASE
            )
        }

        self.weights = {
            "Email": 15,
            "Phone Number": 20,
            "Aadhaar Number": 40,
            "PAN": 35,
            "UPI ID": 25,
            "Credit/Debit Card": 50,
            "Password": 60,
            "API Key": 60
        }

    def detect(self, text):
        text = text or ""
        results = []

        for data_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            if matches:
                results.append({
                    "type": data_type,
                    "count": len(matches)
                })

        return results

    def get_data_types(self, text):
        return [item["type"] for item in self.detect(text)]

    def calculate_sensitivity(self, text):
        detected = self.detect(text)
        score = sum(
            self.weights.get(item["type"], 10)
            for item in detected
        )
        return min(score, 100)

    def anonymize(self, text):
        protected = text or ""

        # Replace high-risk labelled secrets first.
        for name in ("Password", "API Key"):
            protected = self.patterns[name].sub(
                lambda match: match.group(0).split(
                    ":", 1
                )[0].split("=", 1)[0] + "=[REDACTED]",
                protected
            )

        replacements = {
            "Email": "[EMAIL REDACTED]",
            "Phone Number": "[PHONE REDACTED]",
            "Aadhaar Number": "[AADHAAR REDACTED]",
            "PAN": "[PAN REDACTED]",
            "UPI ID": "[UPI ID REDACTED]",
            "Credit/Debit Card": "[CARD REDACTED]"
        }

        # Longer patterns first reduces accidental partial replacements.
        order = [
            "Aadhaar Number",
            "Credit/Debit Card",
            "Phone Number",
            "Email",
            "PAN",
            "UPI ID"
        ]

        for name in order:
            protected = self.patterns[name].sub(
                replacements[name], protected
            )

        return protected