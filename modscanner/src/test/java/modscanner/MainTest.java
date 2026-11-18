package modscanner;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static modscanner.Fixtures.cls;
import static modscanner.Fixtures.jar;
import static modscanner.Fixtures.newObject;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class MainTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int run(String... args) {
        return Main.run(args, new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8));
    }

    private String output() {
        return out.toString(StandardCharsets.UTF_8);
    }

    private Path dir() {
        return tmp.getRoot().toPath();
    }

    /** Scores 16: a hidden URL and a class loader in the main class's static initializer. */
    private Path writeRiskyMod(Path folder) throws IOException {
        return Fixtures.write(folder, "risky.jar", jar(
                "fabric.mod.json", "{\"entrypoints\": {\"main\": [\"com.example.Mod\"]}}",
                "com/example/Mod.class", cls("com/example/Mod").clinit(mv -> {
                    Fixtures.byteArrayString(mv, "http://203.0.113.7:8080/");
                    newObject(mv, "java/net/URLClassLoader", "([Ljava/net/URL;)V");
                }).bytes()));
    }

    private Path writeCleanMod(Path folder) throws IOException {
        return Fixtures.write(folder, "clean.jar", jar("com/example/Clean.class", cls("com/example/Clean").bytes()));
    }

    @Test
    public void textReportForCleanMod() throws IOException {
        assertEquals(Main.EXIT_CLEAN, run(writeCleanMod(dir()).toString()));
        assertTrue(output().contains("Risk: LOW (score 0)"));
        assertTrue(output().contains("No risky behavior found."));
    }

    @Test
    public void textReportForRiskyMod() throws IOException {
        assertEquals(Main.EXIT_FLAGGED, run(writeRiskyMod(dir()).toString()));
        String o = output();
        assertTrue(o.contains("Risk: HIGH (score 16)  ** FLAGGED **"));
        assertTrue(o.contains(Signal.RUNTIME_CLASS_LOADING.plainLanguage));
        assertTrue(o.contains("This happens as soon as the game loads the mod."));
        assertTrue(o.contains("Can download code and then run it. (+3)"));
    }

    @Test
    public void jsonReportHasEvidence() throws IOException {
        assertEquals(Main.EXIT_FLAGGED, run("--json", writeRiskyMod(dir()).toString()));
        JsonObject root = JsonParser.parseString(output()).getAsJsonObject();
        JsonObject result = root.getAsJsonArray("results").get(0).getAsJsonObject();
        assertEquals(16, result.get("score").getAsInt());
        assertEquals("HIGH", result.get("level").getAsString());
        JsonObject finding = result.getAsJsonArray("findings").get(0).getAsJsonObject();
        assertTrue(finding.has("signal") && finding.has("location") && finding.has("evidence")
                && finding.has("loadTime") && finding.has("archive"));
        assertEquals("com.example.Mod", result.getAsJsonArray("entrypoints").get(0).getAsJsonObject()
                .get("className").getAsString());
        assertEquals(10, result.getAsJsonArray("scoreBreakdown").size());
        assertTrue(root.getAsJsonObject("config").has("weights"));
    }

    @Test
    public void directoryScanGivesOneResultPerFile() throws IOException {
        Path folder = Files.createDirectories(dir().resolve("mods/sub"));
        writeRiskyMod(folder);
        writeCleanMod(dir().resolve("mods"));
        Files.writeString(dir().resolve("mods/readme.txt"), "not a mod");
        assertEquals(Main.EXIT_FLAGGED, run("--json", dir().resolve("mods").toString()));
        assertEquals(2, JsonParser.parseString(output()).getAsJsonObject().getAsJsonArray("results").size());
    }

    @Test
    public void directorySummaryInTextMode() throws IOException {
        writeRiskyMod(dir());
        writeCleanMod(dir());
        run(dir().toString());
        assertTrue(output().contains("2 files scanned, 1 flagged."));
    }

    @Test
    public void unreadableFileGivesErrorExitCode() throws IOException {
        Path notJar = Fixtures.write(dir(), "fake.jar", "just text".getBytes(StandardCharsets.UTF_8));
        assertEquals(Main.EXIT_ERROR, run(notJar.toString()));
        assertTrue(output().contains("Could not scan this file: not a ZIP or JAR archive"));
    }

    @Test
    public void configOverrideChangesTheVerdict() throws IOException {
        Path config = dir().resolve("strict.json");
        Files.writeString(config, "{\"thresholds\": {\"high\": 20}}");
        assertEquals(Main.EXIT_CLEAN, run("--config", config.toString(), writeRiskyMod(dir()).toString()));
        assertTrue(output().contains("Risk: MEDIUM (score 16)"));
    }

    @Test
    public void writesReportToFile() throws IOException {
        Path report = dir().resolve("report.json");
        run("--json", "-o", report.toString(), writeCleanMod(dir()).toString());
        assertTrue(Files.readString(report).contains("\"results\""));
    }

    @Test
    public void usageErrors() {
        assertEquals(Main.EXIT_USAGE, run());
        assertEquals(Main.EXIT_USAGE, run("--bogus"));
        assertEquals(Main.EXIT_USAGE, run(dir().resolve("missing.jar").toString()));
    }
}
