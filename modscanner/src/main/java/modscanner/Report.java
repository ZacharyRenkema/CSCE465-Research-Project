package modscanner;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Formats results: a plain-language text report for players, and JSON with all evidence for analysis. */
final class Report {

    private Report() {
    }

    static final String VERSION = "modscanner 0.1.0";

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    /** All results plus the config that produced them, so a run can be reproduced. */
    static String json(List<ScanResult> results, ScanConfig config) {
        JsonObject root = new JsonObject();
        root.addProperty("scanner", VERSION);
        root.add("config", JsonParser.parseString(config.toJson()));
        root.add("results", GSON.toJsonTree(results));
        return GSON.toJson(root);
    }

    static String text(ScanResult r, boolean verbose) {
        StringBuilder sb = new StringBuilder();
        sb.append("== ").append(r.file).append(" ==\n");
        if (r.error != null && r.sha256 == null) {
            sb.append("Could not scan this file: ").append(r.error).append("\n");
            return sb.toString();
        }
        sb.append("Risk: ").append(r.level).append(" (score ").append(r.score).append(")")
                .append(r.flagged ? "  ** FLAGGED **" : "  not flagged").append("\n");
        if (!r.complete) {
            sb.append("Warning: the scan stopped early, so this result may be missing things: ")
                    .append(r.error).append("\n");
        }

        // One line per signal found, in the order of the paper's table.
        Map<Signal, List<Finding>> bySignal = new LinkedHashMap<>();
        for (Signal s : Signal.values()) {
            for (Finding f : r.findings) {
                if (f.signal == s) {
                    bySignal.computeIfAbsent(s, k -> new ArrayList<>()).add(f);
                }
            }
        }
        if (bySignal.isEmpty()) {
            sb.append("\nNo risky behavior found.\n");
        } else {
            sb.append("\nWhat this mod can do:\n");
            for (Map.Entry<Signal, List<Finding>> e : bySignal.entrySet()) {
                List<Finding> fs = e.getValue();
                boolean loadTime = fs.stream().anyMatch(f -> f.loadTime);
                sb.append("  - ").append(e.getKey().plainLanguage);
                if (loadTime) {
                    sb.append(" This happens as soon as the game loads the mod.");
                }
                sb.append("\n");
                Finding first = fs.stream().filter(f -> f.loadTime).findFirst().orElse(fs.get(0));
                List<Finding> shown = verbose ? fs : List.of(first);
                for (Finding f : shown) {
                    sb.append("      ").append(evidenceLine(f)).append("\n");
                }
                if (!verbose && fs.size() > 1) {
                    sb.append("      (and ").append(fs.size() - 1).append(" more; use --verbose to see all)\n");
                }
            }
        }
        if (!r.pairBonuses.isEmpty()) {
            sb.append("\nCombinations that raise the score:\n");
            for (ScanResult.PairBonus p : r.pairBonuses) {
                sb.append("  + ").append(p.reason).append(" (+").append(p.bonus).append(")\n");
            }
        }
        if (!r.notChecked.isEmpty()) {
            sb.append("\nFiles the scanner could not check (it cannot tell you what these do):\n");
            for (ScanResult.Unchecked u : r.notChecked) {
                sb.append("  - ").append(u.path).append(" (").append(u.detail).append(")");
                if (!u.archive.equals(r.archives.get(0))) {
                    sb.append(" in ").append(u.archive);
                }
                sb.append("\n");
            }
        }
        if (verbose) {
            sb.append("\nScore: ");
            List<String> parts = new ArrayList<>();
            for (ScanResult.SignalScore s : r.scoreBreakdown) {
                if (s.points > 0) {
                    parts.add(s.signal.id + " " + s.weight + "x" + s.s);
                }
            }
            r.pairBonuses.forEach(p -> parts.add(p.a.id + "+" + p.b.id + " " + p.bonus));
            sb.append(parts.isEmpty() ? "0" : String.join(" + ", parts)).append(" = ").append(r.score).append("\n");
            sb.append("Loaders: ").append(r.loaders.isEmpty() ? "none found" : String.join(", ", r.loaders)).append("\n");
            for (Entrypoint ep : r.entrypoints) {
                sb.append("Entrypoint: ").append(ep.className).append(" (").append(ep.source)
                        .append(ep.classFound ? "" : ", class missing").append(")\n");
            }
            sb.append("Classes analyzed: ").append(r.classesAnalyzed).append(", archives: ").append(r.archives.size())
                    .append("\nSHA-256: ").append(r.sha256).append("\n");
            r.notes.forEach(n -> sb.append("Note: ").append(n).append("\n"));
        }
        sb.append("\nA low score does not prove a mod is safe. Only install mods from sources you trust.\n");
        return sb.toString();
    }

    private static String evidenceLine(Finding f) {
        String where = f.where();
        if (!f.archive.contains("!/")) {
            return where + ": " + f.evidence;
        }
        return where + ": " + f.evidence + "  [in " + f.archive.substring(f.archive.indexOf("!/") + 2) + "]";
    }

    /** One line per file, for directory scans. */
    static String summary(List<ScanResult> results) {
        StringBuilder sb = new StringBuilder("\n== Summary ==\n");
        int flagged = 0;
        for (ScanResult r : results) {
            String level = r.sha256 == null ? "ERROR" : r.level.name();
            sb.append(String.format("%-7s %4s  %s%s%n", level, r.sha256 == null ? "-" : String.valueOf(r.score),
                    r.file, r.flagged ? "  FLAGGED" : ""));
            if (r.flagged) {
                flagged++;
            }
        }
        sb.append(results.size()).append(" files scanned, ").append(flagged).append(" flagged.\n");
        return sb.toString();
    }
}
