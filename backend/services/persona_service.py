class PersonaService:
    def predict(
        self,
        sensitive_score=0,
        detected_data=None,
        action="",
        destination="",
        source="",
        previous_risk=0,
        analysis_count=0
    ):
        detected_data = detected_data or []
        action = (action or "").lower()
        destination = (destination or "").lower()

        risk = float(sensitive_score) * 0.40
        reasons = []

        if sensitive_score >= 40:
            reasons.append("The submitted content contains high-sensitivity data.")
        elif sensitive_score > 0:
            reasons.append("The submitted content contains potentially sensitive data.")

        if any(term in destination for term in
               ("external ai", "public platform", "external website")):
            risk += 25
            reasons.append("The destination is an external service.")
        elif "external email" in destination:
            risk += 15
            reasons.append("The destination is external email.")

        if any(term in action for term in ("send", "share", "upload")):
            risk += 15
            reasons.append("The activity could transfer data outside its source.")
        elif any(term in action for term in ("download", "copy")):
            risk += 8
            reasons.append("The activity involves copying or downloading data.")

        if previous_risk >= 70:
            risk += 15
            reasons.append("Previous activity had a high risk score.")
        elif previous_risk >= 40:
            risk += 8
            reasons.append("Previous activity had an elevated risk score.")

        if analysis_count >= 10:
            risk += 5
            reasons.append("Repeated activity is considered in the baseline risk estimate.")

        risk = round(min(max(risk, 0), 100), 1)

        if risk >= 80:
            persona = "Compromised Persona"
        elif risk >= 60:
            persona = "High-Risk User"
        elif risk >= 40:
            persona = "Suspicious User"
        elif risk >= 20:
            persona = "Normal User"
        else:
            persona = "Trusted User"

        if not reasons:
            reasons.append("No configured high-risk indicators were detected.")

        return {
            "persona": persona,
            "confidence": round(min(95, 60 + abs(risk - 50) * 0.5), 1),
            "risk_score": risk,
            "trust_score": round(100 - risk, 1),
            "reasons": reasons
        }