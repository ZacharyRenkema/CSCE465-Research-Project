package modscanner;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The scoring numbers. Defaults come from {@code src/main/resources/modscanner/default-config.json},
 * which matches the paper. A file passed with {@code --config} is laid over the defaults, so it only
 * needs the keys it changes, e.g. {@code {"thresholds": {"high": 7}}}.
 */
final class ScanConfig {

    Map<String, Integer> weights = new LinkedHashMap<>();
    /** s_i for a signal found in load-time code (the paper uses 2). */
    int loadTimeMultiplier = 2;
    List<Pair> pairs = new ArrayList<>();
    Thresholds thresholds = new Thresholds();
    /** Lowest level that counts as flagged: LOW, MEDIUM, or HIGH. */
    String flagAt = "HIGH";
    /** How many calls deep load-time code is followed from entrypoint methods (0 = entry methods only). */
    int loadTimeCallDepth = 3;
    List<String> encodedUrlIgnoreHosts = new ArrayList<>();

    static final class Pair {
        String a;
        String b;
        int bonus;
        /** "paper" if the paper states this pair, "proposed" if we added it. */
        String source;
        String reason;
    }

    static final class Thresholds {
        int medium;
        int high;
    }

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    static ScanConfig defaults() {
        return GSON.fromJson(defaultJson(), ScanConfig.class).check();
    }

    static ScanConfig load(Path overrideFile) throws IOException {
        JsonObject merged = defaultJson();
        JsonElement override = JsonParser.parseString(Files.readString(overrideFile, StandardCharsets.UTF_8));
        if (!override.isJsonObject()) {
            throw new IllegalArgumentException("config must be a JSON object");
        }
        for (Map.Entry<String, JsonElement> e : override.getAsJsonObject().entrySet()) {
            if (!merged.has(e.getKey())) {
                throw new IllegalArgumentException("unknown config key '" + e.getKey() + "'");
            }
            // Objects (weights, thresholds) merge key by key; lists and numbers replace the default.
            if (e.getValue().isJsonObject() && merged.get(e.getKey()).isJsonObject()) {
                e.getValue().getAsJsonObject().entrySet()
                        .forEach(inner -> merged.getAsJsonObject(e.getKey()).add(inner.getKey(), inner.getValue()));
            } else {
                merged.add(e.getKey(), e.getValue());
            }
        }
        return GSON.fromJson(merged, ScanConfig.class).check();
    }

    private static JsonObject defaultJson() {
        try (InputStream in = ScanConfig.class.getResourceAsStream("/modscanner/default-config.json")) {
            if (in == null) {
                throw new IllegalStateException("default-config.json is missing from the jar");
            }
            return JsonParser.parseReader(new InputStreamReader(in, StandardCharsets.UTF_8)).getAsJsonObject();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Catches typos in signal names and impossible values. */
    private ScanConfig check() {
        weights.keySet().forEach(Signal::fromId);
        for (Signal s : Signal.values()) {
            if (!weights.containsKey(s.id)) {
                throw new IllegalArgumentException("config has no weight for '" + s.id + "'");
            }
        }
        for (Pair p : pairs) {
            Signal.fromId(p.a);
            Signal.fromId(p.b);
        }
        RiskLevel.valueOf(flagAt);
        if (thresholds.medium > thresholds.high || loadTimeCallDepth < 0) {
            throw new IllegalArgumentException("thresholds.medium must be <= thresholds.high and loadTimeCallDepth >= 0");
        }
        return this;
    }

    int weight(Signal s) {
        return weights.get(s.id);
    }

    String toJson() {
        return GSON.toJson(this);
    }
}
