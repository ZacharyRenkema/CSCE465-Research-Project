package modscanner;

import org.junit.Test;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

import static modscanner.Fixtures.cls;
import static modscanner.Fixtures.invokeStatic;
import static modscanner.Fixtures.invokeVirtual;
import static modscanner.Fixtures.jar;
import static modscanner.Fixtures.ldc;
import static modscanner.Fixtures.newObject;
import static org.junit.Assert.assertEquals;

/**
 * Writes synthetic demo mods to target/demo-mods/ (every build) and checks the level each gets.
 * They contain the API calls and strings the rules look for, but no working code: nothing in them
 * would do anything if run, and the scanner never runs them anyway. Safe to use for a live demo:
 *
 * <pre>java -jar target/modscanner-0.1.0.jar target/demo-mods</pre>
 */
public class DemoModsTest {

    private static final Path DIR = Paths.get("target", "demo-mods");

    private static Path write(String name, byte[] bytes) throws IOException {
        Files.createDirectories(DIR);
        return Fixtures.write(DIR, name, bytes);
    }

    private static RiskLevel level(Path p) {
        return new Scanner(ScanConfig.defaults()).scan(p).level;
    }

    @Test
    public void writeDemoMods() throws IOException {
        // 1. Staged loader: a hidden URL and a class loader in the main class's static initializer.
        Path staged = write("demo-staged-loader.jar", jar(
                "fabric.mod.json", "{\"id\": \"coolcheats\", \"entrypoints\": {\"main\": [\"com.coolcheats.Mod\"]}}",
                "com/coolcheats/Mod.class", cls("com/coolcheats/Mod").clinit(mv -> {
                    Fixtures.byteArrayString(mv, "http://203.0.113.7:8080/");
                    newObject(mv, "java/net/URLClassLoader", "([Ljava/net/URL;)V");
                    invokeVirtual(mv, "java/lang/ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
                }).bytes()));

        // 2. Token stealer: reads the login token and browser logins, sends them to a hidden webhook.
        String hook = Base64.getEncoder().encodeToString(
                "https://discord.com/api/webhooks/000/demo".getBytes(StandardCharsets.UTF_8));
        Path stealer = write("demo-token-stealer.jar", jar(
                "META-INF/mods.toml", "modLoader=\"javafml\"\n[[mods]]\nmodId=\"fpsboost\"\n",
                "com/fpsboost/FpsBoost.class", cls("com/fpsboost/FpsBoost")
                        .annotation("Lnet/minecraftforge/fml/common/Mod;")
                        .method("<init>", "()V", mv -> {
                            invokeVirtual(mv, "net/minecraft/client/User", "m_92547_", "()Ljava/lang/String;");
                            ldc(mv, "\\Google\\Chrome\\User Data\\Default\\Login Data");
                            ldc(mv, hook);
                            invokeVirtual(mv, "java/net/URL", "openConnection", "()Ljava/net/URLConnection;");
                        }).bytes()));

        // 3. Persistence: a server plugin that registers a startup task and runs a program.
        Path persist = write("demo-persistence-plugin.jar", jar(
                "plugin.yml", "name: BetterChat\nmain: com.betterchat.Plugin\nversion: 1.0\n",
                "com/betterchat/Plugin.class", cls("com/betterchat/Plugin").method("onEnable", "()V", mv -> {
                    ldc(mv, "schtasks /create /sc onlogon /tn Updater /tr helper.exe");
                    ldc(mv, "/Library/LaunchAgents/com.betterchat.helper.plist");
                    invokeVirtual(mv, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;");
                }).bytes(),
                "natives/helper.exe", Fixtures.fakeWindowsExecutable()));

        // 4. Update checker: an ordinary mod that contacts its own site, but only when asked.
        Path updater = write("demo-update-checker.jar", jar(
                "fabric.mod.json", "{\"id\": \"minimap\", \"entrypoints\": {\"main\": [\"com.minimap.Minimap\"]}}",
                "com/minimap/Minimap.class", cls("com/minimap/Minimap").method("onInitialize", "()V", mv -> { }).bytes(),
                "com/minimap/UpdateChecker.class", cls("com/minimap/UpdateChecker").method("check", "()V", mv -> {
                    ldc(mv, "https://api.modrinth.com/v2/project/minimap/version");
                    invokeVirtual(mv, "java/net/URL", "openStream", "()Ljava/io/InputStream;");
                }).bytes()));

        // 5. Clean: does nothing risky.
        Path clean = write("demo-clean.jar", jar(
                "fabric.mod.json", "{\"id\": \"morefood\", \"entrypoints\": {\"main\": [\"com.morefood.MoreFood\"]}}",
                "com/morefood/MoreFood.class", cls("com/morefood/MoreFood").method("onInitialize", "()V",
                        mv -> invokeStatic(mv, "com/morefood/Items", "register", "()V")).bytes(),
                "com/morefood/Items.class", cls("com/morefood/Items")
                        .method(Opcodes.ACC_STATIC, "register", "()V", mv -> { }).bytes()));

        assertEquals(RiskLevel.HIGH, level(staged));
        assertEquals(RiskLevel.HIGH, level(stealer));
        assertEquals(RiskLevel.HIGH, level(persist));
        assertEquals(RiskLevel.LOW, level(updater));
        assertEquals(RiskLevel.LOW, level(clean));
    }
}
