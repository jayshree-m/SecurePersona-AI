class DLPService:
    def __init__(self, detector):
        self.detector = detector

    def apply_decision(self, content, decision):
        decision = (decision or "BLOCK").upper()

        if decision == "ALLOW":
            return {
                "protected_content": content,
                "action": "Allowed without modification",
                "allowed": True
            }

        if decision == "ANONYMIZE":
            protected = self.detector.anonymize(content)
            return {
                "protected_content": protected,
                "action": "Sensitive values anonymized",
                "allowed": True
            }

        return {
            "protected_content": "[TRANSFER BLOCKED BY SECUREPERSONA AI]",
            "action": "Transfer blocked by security policy",
            "allowed": False
        }