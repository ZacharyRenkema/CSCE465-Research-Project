package modscanner;

/** Score 0-2 is low, 3-5 medium, 6 or more high (thresholds come from the config). */
public enum RiskLevel {
    LOW, MEDIUM, HIGH;

    static RiskLevel of(int score, ScanConfig.Thresholds t) {
        if (score >= t.high) {
            return HIGH;
        }
        return score >= t.medium ? MEDIUM : LOW;
    }
}
