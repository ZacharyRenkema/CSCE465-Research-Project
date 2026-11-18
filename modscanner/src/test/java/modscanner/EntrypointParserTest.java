package modscanner;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static modscanner.Fixtures.cls;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class EntrypointParserTest {

    private final List<String> loaders = new ArrayList<>();
    private final List<String> notes = new ArrayList<>();

    /** An archive with the given metadata files (name, text pairs) and classes. */
    private List<Entrypoint> parse(String[] metadata, ClassFacts... classes) {
        ModFile.Archive a = new ModFile.Archive("mod.jar", 0);
        for (int i = 0; i < metadata.length; i += 2) {
            a.metadata.put(metadata[i], metadata[i + 1].getBytes(StandardCharsets.UTF_8));
        }
        a.classes.addAll(List.of(classes));
        return EntrypointParser.parse(a, loaders, notes);
    }

    private static String[] files(String... namesAndContents) {
        return namesAndContents;
    }

    private static ClassFacts facts(Fixtures.ClassBuilder b) {
        return ClassAnalyzer.analyze(b.bytes(), "x.class");
    }

    @Test
    public void fabric() {
        List<Entrypoint> eps = parse(files("fabric.mod.json", """
                {
                  // comments are allowed
                  "schemaVersion": 1,
                  "entrypoints": {
                    "main": ["com.example.Mod"],
                    "client": [{"adapter": "kotlin", "value": "com.example.Client::init"}],
                    "modmenu": ["com.example.MenuIntegration"]
                  }
                }"""));
        assertEquals(List.of("fabric"), loaders);
        assertEquals(2, eps.size());
        assertEquals("com.example.Mod", eps.get(0).className);
        assertEquals(List.of("onInitialize"), eps.get(0).methods);
        assertEquals("com.example.Client", eps.get(1).className);
        assertEquals(List.of("onInitializeClient", "init"), eps.get(1).methods);
    }

    @Test
    public void quilt() {
        List<Entrypoint> eps = parse(files("quilt.mod.json",
                "{\"quilt_loader\": {\"entrypoints\": {\"init\": \"com.example.QuiltMod\"}}}"));
        assertEquals(List.of("quilt"), loaders);
        assertEquals("com.example.QuiltMod", eps.get(0).className);
        assertEquals(List.of("onInitialize"), eps.get(0).methods);
    }

    @Test
    public void forgeAndNeoForge() {
        List<Entrypoint> eps = parse(files("META-INF/mods.toml", "modLoader=\"javafml\""),
                facts(cls("com/example/ForgeMod").annotation("Lnet/minecraftforge/fml/common/Mod;")),
                facts(cls("com/example/NeoMod").annotation("Lnet/neoforged/fml/common/Mod;")),
                facts(cls("com/example/Events").annotation("Lnet/minecraftforge/fml/common/Mod$EventBusSubscriber;")));
        assertTrue(loaders.contains("forge"));
        assertTrue(loaders.contains("neoforge"));
        assertEquals(3, eps.size());
        assertEquals("com.example.ForgeMod", eps.get(0).className);
        assertEquals("@EventBusSubscriber annotation", eps.get(2).source);
    }

    @Test
    public void legacyForgeEventHandlers() {
        List<Entrypoint> eps = parse(files("mcmod.info", "[]"),
                facts(cls("com/example/OldMod").annotation("Lnet/minecraftforge/fml/common/Mod;")
                        .annotatedMethod("preInit", "Lnet/minecraftforge/fml/common/Mod$EventHandler;", mv -> { })));
        assertEquals("forge-legacy", eps.get(0).loader);
        assertEquals(List.of("preInit"), eps.get(0).methods);
    }

    @Test
    public void bukkitPaperAndBungee() {
        List<Entrypoint> eps = parse(files(
                "plugin.yml", "name: Example\nmain: com.example.BukkitPlugin\nversion: 1.0\n",
                "paper-plugin.yml", "main: 'com.example.PaperPlugin'\nbootstrapper: com.example.Boot # early\n",
                "bungee.yml", "main: \"com.example.BungeePlugin\"\n"));
        assertEquals(List.of("bukkit", "paper", "bungeecord"), loaders);
        assertEquals(4, eps.size());
        assertEquals(List.of("onLoad", "onEnable"), eps.get(0).methods);
        assertEquals("com.example.Boot", eps.get(2).className);
        assertEquals(List.of("bootstrap"), eps.get(2).methods);
        assertEquals("com.example.BungeePlugin", eps.get(3).className);
    }

    @Test
    public void manifestAttributes() {
        List<Entrypoint> eps = parse(files("META-INF/MANIFEST.MF", """
                Manifest-Version: 1.0
                Main-Class: com.example.Installer
                Premain-Class: com.example.Agent
                TweakClass: com.example.Tweaker
                MixinConfigs: example.mixins.json
                """,
                "example.mixins.json", "{\"package\": \"com.example.mixin\", \"plugin\": \"com.example.MixinPlugin\"}"));
        assertEquals(4, eps.size());
        assertEquals("java-main", eps.get(0).loader);
        assertEquals(List.of("main"), eps.get(0).methods);
        assertEquals("java-agent", eps.get(1).loader);
        assertEquals(List.of("*"), eps.get(2).methods);
        assertEquals("mixin-plugin", eps.get(3).loader);
        assertEquals("com.example.MixinPlugin", eps.get(3).className);
    }

    @Test
    public void loaderServices() {
        List<Entrypoint> eps = parse(files(
                "META-INF/services/cpw.mods.modlauncher.api.ITransformationService", "com.example.Transformer\n# comment\n",
                "META-INF/services/org.slf4j.spi.SLF4JServiceProvider", "com.example.Logging\n"));
        assertEquals(1, eps.size());
        assertEquals("com.example.Transformer", eps.get(0).className);
    }

    @Test
    public void malformedMetadataIsNotedNotThrown() {
        List<Entrypoint> eps = parse(files("fabric.mod.json", "{ this is not json"));
        assertTrue(eps.isEmpty());
        assertEquals(1, notes.size());
    }
}
