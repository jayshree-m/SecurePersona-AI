class RiskEngine:
    def calculate(
        self,
        sensitive_score=0,
        persona_risk=0,
        action="",
        destination="",
        detected_data=None
    ):
        detected_data = detected_data or []
        action_text = (action or "").lower()
        destination_text = (destination or "").lower()

        data_risk = min(max(float(sensitive_score), 0), 100)
        persona_risk = min(max(float(persona_risk), 0), 100)

        if any(term in destination_text for term in
               ("external ai", "public platform")):
            destination_risk = 90
        elif "external website" in destination_text:
            destination_risk = 75
        elif "external email" in destination_text:
            destination_risk = 60
        elif any(term in destination_text for term in
                 ("company cloud", "internal system")):
            destination_risk = 15
        else:
            destination_risk = 25 if destination_text else 0

        if any(term in action_text for term in ("send", "share", "upload")):
            action_risk = 80
        elif any(term in action_text for term in ("download", "copy")):
            action_risk = 45
        elif "view" in action_text:
            action_risk = 10
        else:
            action_risk = 20

        bonus = 10 if len(set(detected_data)) >= 3 else (
            5 if len(set(detected_data)) == 2 else 0
        )

        score = (
            data_risk * 0.40
            + persona_risk * 0.25
            + destination_risk * 0.20
            + action_risk * 0.15
            + bonus
        )
        score = round(min(max(score, 0), 100), 1)

        if score >= 70:
            decision = "BLOCK"
            level = "HIGH"
        elif score >= 40:
            decision = "ANONYMIZE"
            level = "MEDIUM"
        else:
            decision = "ALLOW"
            level = "LOW"

        return {
            "risk_score": score,
            "risk_level": level,
            "decision": decision,
            "data_risk": round(data_risk, 1),
            "persona_risk": round(persona_risk, 1),
            "destination_risk": destination_risk,
            "action_risk": action_risk,
            "reasons": [
                f"Sensitive-data score: {data_risk:.1f}/100",
                f"Persona risk: {persona_risk:.1f}/100",
                f"Destination risk: {destination_risk}/100",
                f"Action risk: {action_risk}/100"
            ]
        }