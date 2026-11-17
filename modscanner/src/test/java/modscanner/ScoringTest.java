package modscanner;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.objectweb.asm.MethodVisitor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static modscanner.Fixtures.cls;
import static modscanner.Fixtures.invokeStatic;
import static modscanner.Fixtures.invokeVirtual;
import static modscanner.Fixtures.jar;
import static modscanner.Fixtures.ldc;
import static modscanner.Fixtures.newObject;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/** Load-time marking, the risk score formula, pairs, thresholds, and the config file. */
public class ScoringTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static final String FABRIC_JSON = "{\"entrypoints\": {\"main\": [\"com.example.Mod\"]}}";

    private ScanResult scan(ScanConfig config, byte[] jarBytes) throws IOException {
        return new Scanner(config).scan(Fixtures.write(tmp.getRoot().toPath(), "mod.jar", jarBytes));
    }

    private ScanResult scan(byte[] jarBytes) throws IOException {
        return scan(ScanConfig.defaults(), jarBytes);
    }

    private static void exec(MethodVisitor mv) {
        invokeVirtual(mv, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;");
    }

    private static int points(ScanResult r, Signal s) {
        return r.scoreBreakdown.stream().filter(x -> x.signal == s).findFirst().orElseThrow().points;
    }

    // ---- load-time code ----

    @Test
    public void signalInEntrypointStaticInitializerCountsDouble() throws IOException {
        ScanResult r = scan(jar("fabric.mod.json", FABRIC_JSON,
                "com/example/Mod.class", cls("com/example/Mod").clinit(ScoringTest::exec).bytes()));
        assertTrue(r.findings.get(0).loadTime);
        assertEquals(4, points(r, Signal.PROCESS_EXECUTION)); // weight 2 x s 2
        assertEquals(4, r.score);
    }

    @Test
    public void sameSignalOutsideLoadTimeCountsOnce() throws IOException {
        ScanResult r = scan(jar("fabric.mod.json", FABRIC_JSON,
                "com/example/Mod.class", cls("com/example/Mod").bytes(),
                "com/example/Other.class", cls("com/example/Other").method("later", "()V", ScoringTest::exec).bytes()));
        assertFalse(r.findings.get(0).loadTime);
        assertEquals(2, r.score);
    }

    @Test
    public void loadTimeFollowsCallsIntoOtherClasses() throws IOException {
        byte[] mod = cls("com/example/Mod").method("onInitialize", "()V",
                mv -> invokeStatic(mv, "com/example/Helper", "start", "()V")).bytes();
        byte[] helper = cls("com/example/Helper")
                .method(org.objectweb.asm.Opcodes.ACC_STATIC, "start", "()V", ScoringTest::exec)
                .clinit(mv -> invokeVirtual(mv, "java/net/URL", "openStream", "()Ljava/io/InputStream;"))
                .bytes();
        byte[] files = jar("fabric.mod.json", FABRIC_JSON, "com/example/Mod.class", mod,
                "com/example/Helper.class", helper);

        ScanResult deep = scan(files);
        assertTrue(deep.findings.stream().allMatch(f -> f.loadTime)); // start() and Helper.<clinit>

        ScanConfig shallow = ScanConfig.defaults();
        shallow.loadTimeCallDepth = 0;
        ScanResult r = scan(shallow, files);
        assertTrue(r.findings.stream().noneMatch(f -> f.loadTime));
    }

    @Test
    public void entrypointInNestedJarIsLoadTime() throws IOException {
        byte[] inner = jar("fabric.mod.json", FABRIC_JSON,
                "com/example/Mod.class", cls("com/example/Mod").clinit(ScoringTest::exec).bytes());
        ScanResult r = scan(jar("META-INF/jars/inner.jar", inner));
        assertTrue(r.findings.get(0).loadTime);
        assertEquals("mod.jar!/META-INF/jars/inner.jar", r.findings.get(0).archive);
    }

    @Test
    public void missingEntrypointClassIsNoted() throws IOException {
        ScanResult r = scan(jar("fabric.mod.json", FABRIC_JSON));
        assertFalse(r.entrypoints.get(0).classFound);
        assertTrue(r.notes.get(0).contains("com.example.Mod"));
    }

    @Test
    public void stagedLoaderInStaticInitializerScoresHigh() throws IOException {
        // A URL hidden in a byte array and a URLClassLoader, in the main class's static initializer.
        ScanResult r = scan(jar("fabric.mod.json", FABRIC_JSON,
                "com/example/Mod.class", cls("com/example/Mod").clinit(mv -> {
                    Fixtures.byteArrayString(mv, "http://203.0.113.7:8080/");
                    newObject(mv, "java/net/URLClassLoader", "([Ljava/net/URL;)V");
                }).bytes()));
        // encoded 2x2 + class loading 2x2 + network 1x2 + pairs (network+loading, encoded+loading) 3+3
        assertEquals(16, r.score);
        assertEquals(RiskLevel.HIGH, r.level);
    }

    // ---- pairs and thresholds ----

    @Test
    public void pairBonusAddsThree() throws IOException {
        // Network (1) + runtime class loading (2) + the paper's pair bonus (3) = 6 = HIGH.
        ScanResult r = scan(jar("com/example/A.class", cls("com/example/A").method("run", "()V", mv -> {
            invokeVirtual(mv, "java/net/URL", "openStream", "()Ljava/io/InputStream;");
            newObject(mv, "java/net/URLClassLoader", "([Ljava/net/URL;)V");
        }).bytes()));
        assertEquals(1, r.pairBonuses.size());
        assertEquals("paper", r.pairBonuses.get(0).source);
        assertEquals(6, r.score);
        assertEquals(RiskLevel.HIGH, r.level);
        assertTrue(r.flagged);
    }

    @Test
    public void thresholds() {
        ScanConfig.Thresholds t = ScanConfig.defaults().thresholds;
        assertEquals(RiskLevel.LOW, RiskLevel.of(0, t));
        assertEquals(RiskLevel.LOW, RiskLevel.of(2, t));
        assertEquals(RiskLevel.MEDIUM, RiskLevel.of(3, t));
        assertEquals(RiskLevel.MEDIUM, RiskLevel.of(5, t));
        assertEquals(RiskLevel.HIGH, RiskLevel.of(6, t));
    }

    @Test
    public void mediumIsNotFlagged() throws IOException {
        // A webhook URL alone: weight 3, MEDIUM, not flagged.
        ScanResult r = scan(jar("com/example/A.class", cls("com/example/A")
                .method("run", "()V", mv -> ldc(mv, "https://discord.com/api/webhooks/1/x")).bytes()));
        assertEquals(3, r.score);
        assertEquals(RiskLevel.MEDIUM, r.level);
        assertFalse(r.flagged);
    }

    @Test
    public void scoreFromFindingsMatchesFormula() {
        // Hand-built findings: network (w1) at load time, sensitive (w3) not, so 1*2 + 3*1 + pair 3 = 8.
        ScanResult r = new ScanResult();
        r.findings = new ArrayList<>(List.of(
                new Finding(Signal.NETWORK_ACCESS, "a", "C", "m", "e", "call", 0, true),
                new Finding(Signal.NETWORK_ACCESS, "a", "C", "n", "e", "call", 0, false),
                new Finding(Signal.SENSITIVE_FILE_ACCESS, "a", "C", "m", "e", "string", 0, false)));
        Scanner.score(r, ScanConfig.defaults());
        assertEquals(8, r.score);
        assertEquals(2, points(r, Signal.NETWORK_ACCESS));
    }

    // ---- config ----

    @Test
    public void defaultsMatchThePaper() {
        ScanConfig c = ScanConfig.defaults();
        assertEquals(1, c.weight(Signal.NETWORK_ACCESS));
        assertEquals(2, c.weight(Signal.PROCESS_EXECUTION));
        assertEquals(3, c.weight(Signal.MODIFIES_OTHER_JARS));
        assertEquals(2, c.loadTimeMultiplier);
        assertEquals(3, c.thresholds.medium);
        assertEquals(6, c.thresholds.high);
        assertEquals("network_access", c.pairs.get(0).a);
        assertTrue(c.pairs.stream().allMatch(p -> p.bonus == 3));
    }

    @Test
    public void overrideFileChangesOnlyWhatItNames() throws IOException {
        Path f = tmp.getRoot().toPath().resolve("override.json");
        Files.writeString(f, "{\"weights\": {\"network_access\": 5}, \"thresholds\": {\"high\": 10}}");
        ScanConfig c = ScanConfig.load(f);
        assertEquals(5, c.weight(Signal.NETWORK_ACCESS));
        assertEquals(2, c.weight(Signal.PROCESS_EXECUTION));
        assertEquals(10, c.thresholds.high);
        assertEquals(3, c.thresholds.medium);
    }

    @Test
    public void overrideFileRejectsTypos() throws IOException {
        Path f = tmp.getRoot().toPath().resolve("bad.json");
        Files.writeString(f, "{\"weights\": {\"network_acess\": 5}}");
        try {
            ScanConfig.load(f);
            fail("expected an error");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("network_acess"));
        }
    }
}
