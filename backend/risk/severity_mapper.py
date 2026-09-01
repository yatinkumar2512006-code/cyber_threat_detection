class SeverityMapper:
    """Maps integer risk scores (0-100) to 4 explicit severity bands."""

    @staticmethod
    def map_score_to_severity(score: int) -> str:
        s = max(0, min(100, score))
        if s < 60:
            return "Low"
        elif s < 70:
            return "Medium"
        elif s <= 85:
            return "High"
        else:
            return "Critical"
