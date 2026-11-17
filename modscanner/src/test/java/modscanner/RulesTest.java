package modscanner;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import static modscanner.Fixtures.cls;
import static modscanner.Fixtures.invokeStatic;
import static modscanner.Fixtures.invokeVirtual;
import static modscanner.Fixtures.jar;
import static modscanner.Fixtures.ldc;
import static modscanner.Fixtures.newObject;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** One test that triggers each signal and at least one benign near miss that must not. */
public class RulesTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private List<Finding> scanJar(byte[] jarBytes) throws IOException {
        ModFile mod = ArchiveReader.read(Fixtures.write(tmp.getRoot().toPath(), "t.jar", jarBytes),
                ArchiveReader.Limits.DEFAULT);
        return new Rules(Rules.DEFAULT_IGNORED_HOSTS).evaluate(mod);
    }

    private Set<Signal> signals(byte[] jarBytes) throws IOException {
        Set<Signal> s = EnumSet.noneOf(Signal.class);
        scanJar(jarBytes).forEach(f -> s.add(f.signal));
        return s;
    }

    /** A JAR holding one class whose run() method has the given body. */
    private Set<Signal> signalsOf(Consumer<MethodVisitor> body) throws IOException {
        return signals(jar("com/example/A.class", cls("com/example/A").method("run", "()V", body).bytes()));
    }

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    // ---- network access ----

    @Test
    public void networkAccess() throws IOException {
        assertTrue(signalsOf(mv -> invokeVirtual(mv, "java/net/URL", "openConnection", "()Ljava/net/URLConnection;"))
                .contains(Signal.NETWORK_ACCESS));
        assertTrue(signalsOf(mv -> invokeVirtual(mv, "com/example/shadow/okhttp3/OkHttpClient", "newCall",
                "(Lokhttp3/Request;)Lokhttp3/Call;")).contains(Signal.NETWORK_ACCESS));
    }

    @Test
    public void networkAccessNearMiss() throws IOException {
        // Building a URL object (e.g. for a "visit our wiki" link) does not connect anywhere.
        assertEquals(Set.of(), signalsOf(mv -> {
            ldc(mv, "https://example.com/wiki");
            newObject(mv, "java/net/URL", "(Ljava/lang/String;)V");
            invokeVirtual(mv, "java/net/URL", "toString", "()Ljava/lang/String;");
        }));
    }

    @Test
    public void urlClassLoaderWithRemoteUrlCountsAsNetwork() throws IOException {
        Set<Signal> s = signalsOf(mv -> {
            Fixtures.byteArrayString(mv, "http://203.0.113.7:8080/stage2");
            newObject(mv, "java/net/URLClassLoader", "([Ljava/net/URL;)V");
        });
        assertTrue(s.containsAll(EnumSet.of(Signal.NETWORK_ACCESS, Signal.RUNTIME_CLASS_LOADING, Signal.ENCODED_STRINGS)));
    }

    // ---- native code ----

    @Test
    public void nativeCode() throws IOException {
        assertTrue(signalsOf(mv -> invokeStatic(mv, "java/lang/System", "loadLibrary", "(Ljava/lang/String;)V"))
                .contains(Signal.NATIVE_CODE));
        assertTrue(signals(jar("natives/helper.dll", Fixtures.fakeWindowsExecutable())).contains(Signal.NATIVE_CODE));
        assertTrue(signals(jar("com/example/N.class", cls("com/example/N")
                .method(Opcodes.ACC_PUBLIC | Opcodes.ACC_NATIVE, "nativeCall", "()V", mv -> { }).bytes()))
                .contains(Signal.NATIVE_CODE));
    }

    @Test
    public void nativeCodeNearMiss() throws IOException {
        // Rendering through Minecraft's own LWJGL bindings is not the mod bringing native code.
        assertEquals(Set.of(), signalsOf(mv -> invokeStatic(mv, "org/lwjgl/opengl/GL11", "glEnable", "(I)V")));
    }

    // ---- obfuscated code ----

    @Test
    public void obfuscatedShortClassNames() throws IOException {
        Object[] entries = new Object[24];
        for (int i = 0; i < 12; i++) {
            String name = "" + (char) ('a' + i);
            entries[2 * i] = name + ".class";
            entries[2 * i + 1] = cls(name).bytes();
        }
        assertTrue(signals(jar(entries)).contains(Signal.OBFUSCATED_CODE));
    }

    @Test
    public void obfuscatedImpossibleNames() throws IOException {
        assertTrue(signals(jar("com/example/A.class", cls("com/example/A")
                .field("if").field("IlIlIlIl").method("do", "()V", mv -> { }).bytes()))
                .contains(Signal.OBFUSCATED_CODE));
    }

    @Test
    public void obfuscatedHiddenOrCorruptFiles() throws IOException {
        assertTrue(signals(jar("assets/data.bin", cls("com/example/P").bytes())).contains(Signal.OBFUSCATED_CODE));
        assertTrue(signals(jar("assets/icon.png", Fixtures.fakeWindowsExecutable())).contains(Signal.OBFUSCATED_CODE));
        assertTrue(signals(jar("com/example/X.class", "garbage")).contains(Signal.OBFUSCATED_CODE));
    }

    @Test
    public void obfuscatedNearMiss() throws IOException {
        // Ordinary names, with a couple of short ones (Vec, IO) and inner classes.
        Object[] entries = new Object[24];
        String[] names = {"Vec", "IO", "ModConfig", "Main", "Network", "Blocks", "Items", "Renderer", "Util",
                "Main$1", "Main$Inner", "Sounds"};
        for (int i = 0; i < names.length; i++) {
            entries[2 * i] = "com/example/" + names[i] + ".class";
            entries[2 * i + 1] = cls("com/example/" + names[i]).field("x").bytes();
        }
        assertFalse(signals(jar(entries)).contains(Signal.OBFUSCATED_CODE));
    }

    // ---- encoded strings ----

    @Test
    public void encodedStrings() throws IOException {
        assertTrue(signalsOf(mv -> ldc(mv, b64("https://203.0.113.7/payload.jar"))).contains(Signal.ENCODED_STRINGS));
        assertTrue(signalsOf(mv -> Fixtures.charArrayString(mv, "java.lang.Runtime")).contains(Signal.ENCODED_STRINGS));
    }

    @Test
    public void encodedStringsNearMiss() throws IOException {
        // Base64 of plain text, a Minecraft skin texture, and a byte array holding an ordinary word.
        assertEquals(Set.of(), signalsOf(mv -> {
            ldc(mv, b64("Thanks for playing!"));
            ldc(mv, b64("{\"textures\":{\"SKIN\":{\"url\":\"http://textures.minecraft.net/texture/abc123\"}}}"));
            Fixtures.byteArrayString(mv, "Hello there");
        }));
        // Plain (not encoded) URLs are not this signal.
        assertEquals(Set.of(), signalsOf(mv -> ldc(mv, "https://modrinth.com/mod/example")));
    }

    // ---- runtime class loading ----

    @Test
    public void runtimeClassLoading() throws IOException {
        assertTrue(signalsOf(mv -> invokeVirtual(mv, "java/lang/invoke/MethodHandles$Lookup", "defineClass",
                "([B)Ljava/lang/Class;")).contains(Signal.RUNTIME_CLASS_LOADING));
        assertTrue(signals(jar("com/example/L.class", new Fixtures.ClassBuilder("com/example/L", "java/lang/ClassLoader")
                .bytes())).contains(Signal.RUNTIME_CLASS_LOADING));
    }

    @Test
    public void runtimeClassLoadingNearMiss() throws IOException {
        // Looking up a class by name (common in compatibility code) loads nothing new.
        assertEquals(Set.of(), signalsOf(mv -> {
            ldc(mv, "net.fabricmc.api.ModInitializer");
            invokeStatic(mv, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;");
            invokeVirtual(mv, "java/lang/ClassLoader", "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        }));
    }

    // ---- process execution ----

    @Test
    public void processExecution() throws IOException {
        assertTrue(signalsOf(mv -> invokeVirtual(mv, "java/lang/Runtime", "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;")).contains(Signal.PROCESS_EXECUTION));
        assertTrue(signalsOf(mv -> newObject(mv, "java/lang/ProcessBuilder", "([Ljava/lang/String;)V"))
                .contains(Signal.PROCESS_EXECUTION));
    }

    @Test
    public void processExecutionThroughMethodReference() throws IOException {
        Handle exec = new Handle(Opcodes.H_INVOKEVIRTUAL, "java/lang/Runtime", "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;", false);
        Set<Signal> s = signalsOf(mv -> ldc(mv, exec));
        assertTrue(s.contains(Signal.PROCESS_EXECUTION));
    }

    @Test
    public void processExecutionThroughReflection() throws IOException {
        List<Finding> f = scanJar(jar("com/example/A.class", cls("com/example/A").method("run", "()V", mv -> {
            Fixtures.charArrayString(mv, "java.lang.Runtime");
            invokeStatic(mv, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;");
            ldc(mv, "exec");
            invokeVirtual(mv, "java/lang/Class", "getMethod",
                    "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
        }).bytes()));
        assertTrue(f.stream().anyMatch(x -> x.signal == Signal.PROCESS_EXECUTION && x.via.equals("reflection")));
    }

    @Test
    public void processExecutionNearMiss() throws IOException {
        // Asking the Runtime for CPU count, and the word "exec" without any reflection.
        assertEquals(Set.of(), signalsOf(mv -> {
            invokeStatic(mv, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;");
            invokeVirtual(mv, "java/lang/Runtime", "availableProcessors", "()I");
            ldc(mv, "java.lang.Runtime");
            ldc(mv, "exec");
        }));
    }

    // ---- webhooks and paste sites ----

    @Test
    public void webhooksOrPasteSites() throws IOException {
        assertTrue(signalsOf(mv -> ldc(mv, "https://discord.com/api/webhooks/123/abc"))
                .contains(Signal.WEBHOOKS_OR_PASTE_SITES));
        assertTrue(signalsOf(mv -> ldc(mv, "https://pastebin.com/raw/xyz")).contains(Signal.WEBHOOKS_OR_PASTE_SITES));
        assertTrue(signalsOf(mv -> ldc(mv, "https://api.telegram.org/bot123:abc/sendMessage"))
                .contains(Signal.WEBHOOKS_OR_PASTE_SITES));
    }

    @Test
    public void webhooksNearMiss() throws IOException {
        // A Discord invite link and a GitHub link, as found in many mod menus.
        assertEquals(Set.of(), signalsOf(mv -> {
            ldc(mv, "https://discord.gg/example");
            ldc(mv, "https://github.com/example/mod/issues");
        }));
    }

    // ---- sensitive file access ----

    @Test
    public void sensitiveFileAccess() throws IOException {
        assertTrue(signalsOf(mv -> ldc(mv, "\\Google\\Chrome\\User Data\\Default\\Login Data"))
                .contains(Signal.SENSITIVE_FILE_ACCESS));
        assertTrue(signalsOf(mv -> ldc(mv, "Library/Application Support/Firefox/Profiles"))
                .contains(Signal.SENSITIVE_FILE_ACCESS));
        assertTrue(signalsOf(mv -> ldc(mv, "discord\\Local Storage\\leveldb")).contains(Signal.SENSITIVE_FILE_ACCESS));
    }

    @Test
    public void sessionTokenRead() throws IOException {
        // Fabric intermediary name of Session.getAccessToken.
        assertTrue(signalsOf(mv -> invokeVirtual(mv, "net/minecraft/class_320", "method_1674", "()Ljava/lang/String;"))
                .contains(Signal.SENSITIVE_FILE_ACCESS));
    }

    @Test
    public void sensitiveNearMiss() throws IOException {
        // Reading the player's name from the same Session class is ordinary (Session.getUsername).
        assertEquals(Set.of(), signalsOf(mv -> {
            invokeVirtual(mv, "net/minecraft/class_320", "method_1676", "()Ljava/lang/String;");
            ldc(mv, "config/examplemod/settings.json");
            ldc(mv, "Local Storage is used for settings");
        }));
    }

    // ---- persistence paths ----

    @Test
    public void persistencePaths() throws IOException {
        assertTrue(signalsOf(mv -> ldc(mv, "Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
                .contains(Signal.PERSISTENCE_PATHS));
        assertTrue(signalsOf(mv -> ldc(mv, "/Library/LaunchAgents/com.example.helper.plist"))
                .contains(Signal.PERSISTENCE_PATHS));
        assertTrue(signalsOf(mv -> ldc(mv, "~/.config/systemd/user/helper.service")).contains(Signal.PERSISTENCE_PATHS));
    }

    @Test
    public void persistenceNearMiss() throws IOException {
        assertEquals(Set.of(), signalsOf(mv -> {
            ldc(mv, "config/startup-screen.json");
            ldc(mv, "Running on Windows");
        }));
    }

    // ---- modifies other JARs ----

    @Test
    public void modifiesOtherJars() throws IOException {
        assertTrue(signalsOf(mv -> {
            ldc(mv, ".jar");
            newObject(mv, "java/util/jar/JarOutputStream", "(Ljava/io/OutputStream;)V");
        }).contains(Signal.MODIFIES_OTHER_JARS));
    }

    @Test
    public void modifiesOtherJarsNearMiss() throws IOException {
        // A world backup mod writes .zip files, not .jar files.
        assertEquals(Set.of(), signalsOf(mv -> {
            ldc(mv, "backups/world.zip");
            newObject(mv, "java/util/zip/ZipOutputStream", "(Ljava/io/OutputStream;)V");
        }));
    }

    // ---- evidence details ----

    @Test
    public void findingsCarryLocationAndNestedArchive() throws IOException {
        byte[] inner = jar("lib/Helper.class", cls("lib/Helper").method("go", "()V",
                mv -> invokeVirtual(mv, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;")).bytes());
        List<Finding> f = scanJar(jar("META-INF/jars/helper.jar", inner));
        assertEquals(1, f.size());
        assertEquals("t.jar!/META-INF/jars/helper.jar", f.get(0).archive);
        assertEquals("lib.Helper", f.get(0).location);
        assertEquals("go", f.get(0).method);
        assertEquals("java.lang.Runtime.exec", f.get(0).evidence);
    }

    @Test
    public void repeatedEvidenceIsReportedOnce() throws IOException {
        List<Finding> f = scanJar(jar("com/example/A.class", cls("com/example/A").method("run", "()V", mv -> {
            for (int i = 0; i < 5; i++) {
                invokeVirtual(mv, "java/net/URL", "openStream", "()Ljava/io/InputStream;");
            }
        }).bytes()));
        assertEquals(1, f.size());
    }
}
