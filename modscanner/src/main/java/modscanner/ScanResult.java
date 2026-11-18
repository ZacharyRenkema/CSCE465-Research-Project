package modscanner;

import java.util.ArrayList;
import java.util.List;

/** The result of scanning one file. Field order is the order of the JSON report. */
public final class ScanResult {
    public String file;
    public String sha256;
    public long sizeBytes;
    /** False if the file was rejected or the scan stopped early. */
    public boolean complete = true;
    public String error;

    public int score;
    public RiskLevel level = RiskLevel.LOW;
    public boolean flagged;
    /** w_i, s_i, and w_i * s_i for every signal, so the score can be checked by hand. */
    public List<SignalScore> scoreBreakdown = new ArrayList<>();
    public List<PairBonus> pairBonuses = new ArrayList<>();

    public List<Finding> findings = new ArrayList<>();
    public List<String> loaders = new ArrayList<>();
    public List<Entrypoint> entrypoints = new ArrayList<>();
    /** Files listed but not analyzed: native files, scripts, unreadable classes, too-deep archives. */
    public List<Unchecked> notChecked = new ArrayList<>();
    public List<String> archives = new ArrayList<>();
    public int classesAnalyzed;
    public List<String> notes = new ArrayList<>();

    public static final class SignalScore {
        public Signal signal;
        public int weight;
        /** 0 absent, 1 present, loadTimeMultiplier (2) present in load-time code. */
        public int s;
        public int points;
        public int findings;
    }

    public static final class PairBonus {
        public Signal a;
        public Signal b;
        public int bonus;
        public String source;
        public String reason;
    }

    public static final class Unchecked {
        public String archive;
        public String path;
        public String kind;
        public String detail;
    }
}
