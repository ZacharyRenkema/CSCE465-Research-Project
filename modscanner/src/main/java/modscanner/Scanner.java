package modscanner;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Runs the whole pipeline for one file: read, find entrypoints, mark load-time code, apply rules, score. */
final class Scanner {

    private final ScanConfig config;
    private final Rules rules;

    Scanner(ScanConfig config) {
        this.config = config;
        this.rules = new Rules(Set.copyOf(config.encodedUrlIgnoreHosts));
    }

    /** Never throws: a bug triggered by one strange file becomes an error result, so a folder scan keeps going. */
    ScanResult scan(Path file) {
        try {
            return scanOrThrow(file);
        } catch (RuntimeException e) {
            ScanResult r = new ScanResult();
            r.file = file.toString();
            r.complete = false;
            r.error = "internal scanner error: " + e;
            return r;
        }
    }

    private ScanResult scanOrThrow(Path file) {
        ScanResult r = new ScanResult();
        r.file = file.toString();
        ModFile mod;
        try {
            mod = ArchiveReader.read(file, ArchiveReader.Limits.DEFAULT);
        } catch (IOException e) {
            r.complete = false;
            r.error = e.getMessage();
            return r;
        }
        r.sha256 = mod.sha256;
        r.sizeBytes = mod.size;
        r.complete = mod.complete;
        r.notes.addAll(mod.problems);
        if (!mod.complete && !mod.problems.isEmpty()) {
            r.error = mod.problems.get(0);
        }
        r.classesAnalyzed = mod.classCount();

        for (ModFile.Archive archive : mod.archives) {
            r.archives.add(archive.path);
            List<Entrypoint> eps = EntrypointParser.parse(archive, r.loaders, r.notes);
            LoadTime.mark(archive, eps, config.loadTimeCallDepth);
            for (Entrypoint ep : eps) {
                if (!ep.classFound) {
                    r.notes.add(ep.source + " names " + ep.className + ", which is not in " + archive.path);
                }
            }
            r.entrypoints.addAll(eps);
            for (ModFile.NotableFile f : archive.notableFiles) {
                if (f.kind() != ModFile.FileKind.HIDDEN_CLASS) {
                    ScanResult.Unchecked u = new ScanResult.Unchecked();
                    u.archive = archive.path;
                    u.path = f.path();
                    u.kind = f.kind().name().toLowerCase().replace('_', '-');
                    u.detail = f.detail();
                    r.notChecked.add(u);
                }
            }
        }

        r.findings = rules.evaluate(mod);
        score(r, config);
        return r;
    }

    /** R = sum of w_i * s_i, plus b_j for every pair j whose two signals were both found. */
    static void score(ScanResult r, ScanConfig config) {
        Set<Signal> present = new HashSet<>();
        int total = 0;
        r.scoreBreakdown = new ArrayList<>();
        r.pairBonuses = new ArrayList<>();
        for (Signal signal : Signal.values()) {
            ScanResult.SignalScore s = new ScanResult.SignalScore();
            s.signal = signal;
            s.weight = config.weight(signal);
            for (Finding f : r.findings) {
                if (f.signal == signal) {
                    s.findings++;
                    s.s = Math.max(s.s, f.loadTime ? config.loadTimeMultiplier : 1);
                }
            }
            s.points = s.weight * s.s;
            total += s.points;
            if (s.s > 0) {
                present.add(signal);
            }
            r.scoreBreakdown.add(s);
        }
        for (ScanConfig.Pair p : config.pairs) {
            if (present.contains(Signal.fromId(p.a)) && present.contains(Signal.fromId(p.b))) {
                ScanResult.PairBonus b = new ScanResult.PairBonus();
                b.a = Signal.fromId(p.a);
                b.b = Signal.fromId(p.b);
                b.bonus = p.bonus;
                b.source = p.source;
                b.reason = p.reason;
                r.pairBonuses.add(b);
                total += p.bonus;
            }
        }
        r.score = total;
        r.level = RiskLevel.of(total, config.thresholds);
        r.flagged = r.level.compareTo(RiskLevel.valueOf(config.flagAt)) >= 0;
    }
}
