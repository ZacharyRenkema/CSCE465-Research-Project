package modscanner;

import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The detection rules for the ten signals. Every rule describes a capability (an API or a kind of
 * path or service), never a particular malware family. Rules only read {@link ModFile} and
 * {@link ClassFacts}; whether code is load-time must already be marked on each method.
 */
final class Rules {

    // ------------------------------------------------------------------
    // API calls. "owner#name". An owner starting with "*" matches any owner ending in the rest, which
    // catches libraries shaded into another package. An owner of just "*" matches every owner.
    // ------------------------------------------------------------------

    record Api(Signal signal, String owner, String name) {
        boolean matches(String callOwner, String callName) {
            if (!name.equals(callName)) {
                return false;
            }
            if (owner.equals("*")) {
                return true;
            }
            return owner.startsWith("*") ? callOwner.endsWith(owner.substring(1)) : owner.equals(callOwner);
        }

        boolean exactOwner() {
            return !owner.startsWith("*");
        }
    }

    private static final List<Api> APIS = new ArrayList<>();

    private static void apis(Signal signal, String... specs) {
        for (String spec : specs) {
            String[] parts = spec.split("#");
            APIS.add(new Api(signal, parts[0], parts[1]));
        }
    }

    static {
        apis(Signal.NETWORK_ACCESS,
                "java/net/URL#openConnection", "java/net/URL#openStream", "java/net/URL#getContent",
                "java/net/Socket#<init>", "java/net/Socket#connect",
                "javax/net/SocketFactory#createSocket", "javax/net/ssl/SSLSocketFactory#createSocket",
                "java/net/ServerSocket#<init>", "java/net/DatagramSocket#<init>", "java/net/DatagramSocket#send",
                "java/nio/channels/SocketChannel#open", "java/nio/channels/AsynchronousSocketChannel#open",
                "java/nio/channels/DatagramChannel#open",
                "java/net/http/HttpClient#send", "java/net/http/HttpClient#sendAsync",
                "java/net/http/HttpClient#newWebSocketBuilder",
                "*okhttp3/OkHttpClient#newCall", "*okhttp3/OkHttpClient#newWebSocket",
                "*org/apache/http/client/HttpClient#execute",
                "*org/apache/http/impl/client/CloseableHttpClient#execute",
                "*org/apache/hc/client5/http/impl/classic/CloseableHttpClient#execute",
                "*io/netty/bootstrap/Bootstrap#connect");

        apis(Signal.NATIVE_CODE,
                "java/lang/System#load", "java/lang/System#loadLibrary",
                "java/lang/Runtime#load", "java/lang/Runtime#loadLibrary",
                "*com/sun/jna/Native#load", "*com/sun/jna/Native#loadLibrary", "*com/sun/jna/Native#register",
                "*com/sun/jna/NativeLibrary#getInstance",
                "java/lang/foreign/Linker#nativeLinker", "java/lang/foreign/SymbolLookup#libraryLookup",
                "org/lwjgl/system/Library#loadSystem", "org/lwjgl/system/Library#loadNative");

        apis(Signal.RUNTIME_CLASS_LOADING,
                // Any defineClass: ClassLoader, Unsafe, MethodHandles.Lookup, or the mod's own loader.
                "*#defineClass", "*#defineHiddenClass", "*#defineAnonymousClass",
                "java/lang/ClassLoader#defineClass", "java/lang/invoke/MethodHandles$Lookup#defineClass",
                "java/net/URLClassLoader#<init>", "java/net/URLClassLoader#newInstance",
                "javax/script/ScriptEngine#eval", "*groovy/lang/GroovyShell#evaluate",
                "*org/mozilla/javascript/Context#evaluateString",
                "java/lang/instrument/Instrumentation#redefineClasses",
                "java/lang/instrument/Instrumentation#retransformClasses",
                "java/lang/instrument/Instrumentation#addTransformer",
                "java/lang/instrument/Instrumentation#appendToSystemClassLoaderSearch",
                "java/lang/instrument/Instrumentation#appendToBootstrapClassLoaderSearch");

        apis(Signal.PROCESS_EXECUTION,
                "java/lang/Runtime#exec", "java/lang/ProcessBuilder#<init>", "java/lang/ProcessBuilder#start",
                "java/lang/ProcessBuilder#startPipeline", "*org/apache/commons/exec/DefaultExecutor#execute");

        // Reading the Minecraft login (session) token. Names checked against the official mappings:
        // Fabric/Quilt intermediary (1.21.1), Forge SRG and Mojang names (1.20.1), MCP (1.8.9).
        apis(Signal.SENSITIVE_FILE_ACCESS,
                "net/minecraft/class_320#method_1674", "net/minecraft/class_320#method_1675",
                "net/minecraft/client/User#m_92547_", "net/minecraft/client/User#m_92544_",
                "net/minecraft/client/User#getAccessToken", "net/minecraft/client/User#getSessionId",
                "net/minecraft/util/Session#func_148254_d", "net/minecraft/util/Session#func_111286_b",
                "net/minecraft/util/Session#getToken", "net/minecraft/util/Session#getSessionID");
    }

    /** Calls that look up classes or methods by name. Used to resolve reflective calls. */
    private static final Set<String> REFLECTION_APIS = Set.of(
            "java/lang/Class#forName", "java/lang/Class#getMethod", "java/lang/Class#getDeclaredMethod",
            "java/lang/Class#getConstructor", "java/lang/Class#getDeclaredConstructor",
            "java/lang/reflect/Method#invoke", "java/lang/ClassLoader#loadClass",
            "java/lang/invoke/MethodHandles$Lookup#findVirtual", "java/lang/invoke/MethodHandles$Lookup#findStatic",
            "java/lang/invoke/MethodHandles$Lookup#findConstructor", "java/lang/invoke/MethodHandles$Lookup#findSpecial");

    private static final Set<String> CLASS_LOADER_TYPES =
            Set.of("java/lang/ClassLoader", "java/security/SecureClassLoader", "java/net/URLClassLoader");

    /** Writing ZIP/JAR files. Opening a zip file system only counts if the class also writes files. */
    private static final Set<String> ZIP_WRITERS = Set.of(
            "java/util/zip/ZipOutputStream#<init>", "java/util/jar/JarOutputStream#<init>");
    private static final Set<String> FILE_WRITERS = Set.of(
            "java/nio/file/Files#write", "java/nio/file/Files#copy", "java/nio/file/Files#move",
            "java/nio/file/Files#newOutputStream", "java/io/FileOutputStream#<init>");

    // ------------------------------------------------------------------
    // Strings. Matched against every string (decoded ones included) after lower-casing and turning
    // backslashes into slashes, so one pattern covers Windows, macOS, and Linux paths.
    // ------------------------------------------------------------------

    private static final List<Pattern> WEBHOOKS_AND_PASTE_SITES = patterns(
            "discord(?:app)?\\.com/api/(?:v\\d+/)?webhooks", "(?:cdn|media)\\.discordapp\\.(?:com|net)/attachments",
            "api\\.telegram\\.org/bot", "hooks\\.slack\\.com/services", "webhook\\.site", "pipedream\\.net",
            "requestbin\\.", "ngrok(?:-free)?\\.(?:io|app|dev)",
            "pastebin\\.com", "paste\\.ee", "hastebin\\.", "rentry\\.(?:co|org)", "ghostbin\\.", "controlc\\.com",
            "termbin\\.com", "transfer\\.sh", "gofile\\.io", "anonfiles\\.", "(?<![a-z0-9.-])file\\.io");

    /** Where browsers, Discord, Minecraft launchers, and wallets keep logins, on Windows, macOS, and Linux. */
    private static final List<String> SENSITIVE_PATHS = List.of(
            // browsers
            "login data", "local state", "web data", "network/cookies", "key4.db", "logins.json", "cookies.sqlite",
            "google/chrome/user data", "microsoft/edge/user data", "bravesoftware", "opera software",
            "yandex/yandexbrowser", "mozilla/firefox/profiles", "application support/google/chrome",
            "application support/firefox", ".config/google-chrome", ".mozilla/firefox", "library/keychains",
            // Discord
            "discord/local storage", "local storage/leveldb", "discordcanary", "discordptb", "dqw4w9wgxcq:",
            // Minecraft launchers
            "launcher_accounts", "launcher_msa_credentials", ".lunarclient", "feather/accounts.json",
            "essential/microsoft_accounts", "tlauncher_profiles", "prismlauncher/accounts.json",
            "polymc/accounts.json", "multimc/accounts.json",
            // wallets and other apps
            "wallet.dat", "exodus.wallet", "electrum/wallets", "telegram desktop/tdata", "loginusers.vdf",
            "filezilla/recentservers.xml");

    /** Ways to make a program start with the computer, on Windows, macOS, and Linux. */
    private static final List<String> PERSISTENCE_PATHS = List.of(
            "start menu/programs/startup", "shell:startup", "currentversion/run", "currentversion/winlogon",
            "currentversion/policies/explorer/run", "image file execution options", "schtasks",
            "library/launchagents", "library/launchdaemons", "launchctl",
            "/etc/systemd/", ".config/systemd/user", "systemctl enable", "systemctl --user", ".config/autostart",
            "crontab", "/etc/cron", "/etc/rc.local", "/etc/init.d/", ".bashrc", ".bash_profile", ".zshrc");

    // What makes a decoded string worth reporting: it names a place, a program, or Java internals.
    private static final Pattern URL = Pattern.compile("\\b(?:https?|ftp|wss?)://");
    private static final Pattern IPV4 = Pattern.compile("\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b");
    private static final Pattern DOMAIN = Pattern.compile(
            "\\b[a-z0-9-]+\\.(?:com|net|org|io|ru|xyz|gg|app|dev|me|top|cc|site|online|info|biz|cn|su|tk|pw|club|live|link|to|sh)\\b");
    private static final Pattern JDK_CLASS = Pattern.compile("\\b(?:java|javax|sun|jdk)\\.[a-z]+\\.");
    private static final Pattern PROGRAM = Pattern.compile(
            "\\.(?:exe|dll|jar|bat|ps1|vbs|sh|dylib|so)\\b|cmd\\.exe|powershell|/bin/(?:ba)?sh|rundll32|osascript");

    private static final Set<String> JAVA_KEYWORDS = Set.of(
            "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue",
            "default", "do", "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if",
            "implements", "import", "instanceof", "int", "interface", "long", "native", "new", "package", "private",
            "protected", "public", "return", "short", "static", "super", "switch", "synchronized", "this", "throw",
            "throws", "transient", "try", "void", "volatile", "while");

    /** URLs on these hosts do not make an encoded string suspicious (Minecraft skins are Base64 JSON). */
    static final Set<String> DEFAULT_IGNORED_HOSTS = Set.of("textures.minecraft.net");

    private final Set<String> ignoredHosts;

    Rules(Set<String> ignoredHosts) {
        this.ignoredHosts = ignoredHosts;
    }

    // ------------------------------------------------------------------

    /** Collects findings, dropping exact repeats (same signal, place, and evidence). */
    private static final class Out {
        final Map<String, Finding> findings = new LinkedHashMap<>();
        String archive;

        void add(Signal s, String location, String method, String evidence, String via, int line, boolean loadTime) {
            Finding f = new Finding(s, archive, location, method, evidence, via, line, loadTime);
            findings.putIfAbsent(s + "|" + f.where() + "|" + evidence + "|" + loadTime, f);
        }
    }

    List<Finding> evaluate(ModFile mod) {
        Out out = new Out();
        for (ModFile.Archive archive : mod.archives) {
            out.archive = archive.path;
            checkFiles(archive, out);
            checkNames(archive, out);
            for (ClassFacts c : archive.classes) {
                checkClass(c, out);
            }
        }
        return new ArrayList<>(out.findings.values());
    }

    /** Native files are code we cannot read; disguised or unparseable files are a sign of hiding. */
    private static void checkFiles(ModFile.Archive archive, Out out) {
        for (ModFile.NotableFile f : archive.notableFiles) {
            switch (f.kind()) {
                case NATIVE -> out.add(Signal.NATIVE_CODE, f.path(), null, "bundled native file (" + f.detail() + ")",
                        "file", 0, false);
                case DISGUISED_NATIVE -> {
                    out.add(Signal.NATIVE_CODE, f.path(), null, "bundled " + f.detail(), "file", 0, false);
                    out.add(Signal.OBFUSCATED_CODE, f.path(), null, "program disguised as another file type: "
                            + f.detail(), "file", 0, false);
                }
                case BAD_CLASS -> out.add(Signal.OBFUSCATED_CODE, f.path(), null,
                        "class file that cannot be read (" + f.detail() + ")", "file", 0, false);
                case HIDDEN_CLASS -> out.add(Signal.OBFUSCATED_CODE, f.path(), null, f.detail(), "file", 0, false);
                default -> {
                    // Scripts and too-deep archives are listed in the report but are not a signal.
                }
            }
        }
    }

    /**
     * Obfuscators rename classes to "a", "b", ... and sometimes to names javac could never produce.
     * Fires if at least half of 10+ top-level classes have names of one or two characters, or if three
     * or more classes, methods, or fields have impossible names.
     */
    private static void checkNames(ModFile.Archive archive, Out out) {
        int topLevel = 0;
        int shortNames = 0;
        List<String> impossible = new ArrayList<>();
        for (ClassFacts c : archive.classes) {
            String simple = c.name.substring(c.name.lastIndexOf('/') + 1);
            if (!simple.contains("$")) {
                topLevel++;
                if (simple.length() <= 2) {
                    shortNames++;
                }
            }
            List<String> names = new ArrayList<>(List.of(simple.split("\\$")));
            names.addAll(c.fieldNames);
            c.methods.forEach(m -> names.add(m.name));
            for (String n : names) {
                if (isImpossibleName(n)) {
                    impossible.add(c.dottedName() + ": " + printable(n));
                }
            }
        }
        if (topLevel >= 10 && shortNames * 2 >= topLevel) {
            out.add(Signal.OBFUSCATED_CODE, archive.path, null, shortNames + " of " + topLevel
                    + " classes have one- or two-letter names", "class", 0, false);
        }
        if (impossible.size() >= 3) {
            out.add(Signal.OBFUSCATED_CODE, archive.path, null, impossible.size()
                    + " names a Java compiler could not produce, e.g. " + impossible.get(0), "class", 0, false);
        }
    }

    private static boolean isImpossibleName(String n) {
        if (n.isEmpty() || n.equals("<init>") || n.equals("<clinit>") || n.equals("<fields>")) {
            return false;
        }
        if (JAVA_KEYWORDS.contains(n) || n.matches("[Il1]{6,}")) {
            return true;
        }
        for (char ch : n.toCharArray()) {
            if (!Character.isJavaIdentifierPart(ch) || Character.isIdentifierIgnorable(ch)) {
                return true;
            }
        }
        return false;
    }

    private void checkClass(ClassFacts c, Out out) {
        String cls = c.dottedName();
        boolean initLoadTime = false;
        for (ClassFacts.Method m : c.methods) {
            initLoadTime |= m.loadTime && (m.name.equals("<clinit>") || m.name.equals("<init>"));
        }

        if (CLASS_LOADER_TYPES.contains(c.superName)) {
            out.add(Signal.RUNTIME_CLASS_LOADING, cls, null, "is its own class loader (extends "
                    + c.superName.replace('/', '.') + ")", "class", 0, initLoadTime);
        }
        for (String iface : c.interfaces) {
            if (iface.endsWith("com/sun/jna/Library")) {
                out.add(Signal.NATIVE_CODE, cls, null, "binds a native library through JNA", "class", 0, initLoadTime);
            }
        }

        ClassFacts.Method reflectionMethod = null;
        ClassFacts.Method zipWriterMethod = null;
        ClassFacts.Method urlLoaderMethod = null;
        boolean writesFiles = false;
        boolean opensZipFileSystem = false;
        boolean usesAsmWriter = false;
        boolean mentionsJar = false;
        boolean hasRemoteUrl = false;
        Set<String> allStrings = new HashSet<>();

        for (ClassFacts.Method m : c.methods) {
            if ((m.access & Opcodes.ACC_NATIVE) != 0) {
                out.add(Signal.NATIVE_CODE, cls, m.name, "declares a native (JNI) method", "class", 0, m.loadTime);
            }
            for (ClassFacts.Call call : m.calls) {
                for (Api api : APIS) {
                    if (api.matches(call.owner(), call.name())) {
                        out.add(api.signal(), cls, m.name, call.owner().replace('/', '.') + "." + call.name(),
                                call.methodRef() ? "method_ref" : "call", call.line(), m.loadTime);
                    }
                }
                String key = call.owner() + "#" + call.name();
                if (REFLECTION_APIS.contains(key) && (reflectionMethod == null || m.loadTime)) {
                    reflectionMethod = m;
                }
                if (ZIP_WRITERS.contains(key) && zipWriterMethod == null) {
                    zipWriterMethod = m;
                }
                opensZipFileSystem |= key.equals("java/nio/file/FileSystems#newFileSystem");
                writesFiles |= FILE_WRITERS.contains(key);
                usesAsmWriter |= call.owner().endsWith("org/objectweb/asm/ClassWriter");
                if (key.startsWith("java/net/URLClassLoader#") && urlLoaderMethod == null) {
                    urlLoaderMethod = m;
                }
            }
            for (ClassFacts.Str s : m.strings) {
                checkString(cls, m, s, out);
                String n = Strings.normalize(s.value());
                mentionsJar |= n.contains(".jar");
                hasRemoteUrl |= n.contains("http://") || n.contains("https://") || n.contains("ftp://");
                allStrings.add(s.value().trim());
            }
        }

        // Reflection: Class.forName("java.lang.Runtime") plus the string "exec" in the same class is
        // treated as a call to Runtime.exec.
        if (reflectionMethod != null) {
            for (Api api : APIS) {
                if (!api.exactOwner()) {
                    continue;
                }
                boolean ownerNamed = allStrings.contains(api.owner().replace('/', '.')) || allStrings.contains(api.owner());
                boolean memberNamed = api.name().equals("<init>") || allStrings.contains(api.name());
                if (ownerNamed && memberNamed) {
                    out.add(api.signal(), cls, reflectionMethod.name, "reflection: "
                            + api.owner().replace('/', '.') + "." + api.name(), "reflection", 0, reflectionMethod.loadTime);
                }
            }
        }

        // A class loader pointed at a web address downloads the code it loads.
        if (urlLoaderMethod != null && hasRemoteUrl) {
            out.add(Signal.NETWORK_ACCESS, cls, urlLoaderMethod.name, "URLClassLoader with a remote URL", "call", 0,
                    urlLoaderMethod.loadTime);
        }

        // Spreading: writes ZIP/JAR files and either names .jar files or generates bytecode.
        ClassFacts.Method writer = zipWriterMethod;
        if (writer == null && opensZipFileSystem && writesFiles) {
            writer = c.methods.stream().filter(m -> m.calls.stream().anyMatch(
                    call -> (call.owner() + "#" + call.name()).equals("java/nio/file/FileSystems#newFileSystem")))
                    .findFirst().orElse(null);
        }
        if (writer != null && (mentionsJar || usesAsmWriter)) {
            out.add(Signal.MODIFIES_OTHER_JARS, cls, writer.name, "writes ZIP/JAR files and "
                    + (mentionsJar ? "refers to .jar files" : "generates bytecode"), "call", 0, writer.loadTime);
        }
    }

    private void checkString(String cls, ClassFacts.Method m, ClassFacts.Str s, Out out) {
        String n = Strings.normalize(s.value());
        String shown = "\"" + printable(s.value()) + "\"" + (s.origin() == ClassFacts.Origin.LITERAL ? ""
                : " (" + s.origin().name().toLowerCase() + ")");
        for (Pattern p : WEBHOOKS_AND_PASTE_SITES) {
            if (p.matcher(n).find()) {
                out.add(Signal.WEBHOOKS_OR_PASTE_SITES, cls, m.name, shown, "string", s.line(), m.loadTime);
                break;
            }
        }
        for (String path : SENSITIVE_PATHS) {
            if (n.contains(path)) {
                out.add(Signal.SENSITIVE_FILE_ACCESS, cls, m.name, shown, "string", s.line(), m.loadTime);
                break;
            }
        }
        for (String path : PERSISTENCE_PATHS) {
            if (n.contains(path)) {
                out.add(Signal.PERSISTENCE_PATHS, cls, m.name, shown, "string", s.line(), m.loadTime);
                break;
            }
        }
        if (s.origin().isEncoded() && isWorthHiding(n)) {
            out.add(Signal.ENCODED_STRINGS, cls, m.name, shown, "string", s.line(), m.loadTime);
        }
    }

    /** True if decoded text names a web address, IP, program, Java internal class, or one of the paths above. */
    private boolean isWorthHiding(String normalized) {
        String n = normalized;
        for (String host : ignoredHosts) {
            n = n.replaceAll("[a-z]+://" + Pattern.quote(host) + "\\S*", "");
        }
        if (URL.matcher(n).find() || IPV4.matcher(n).find() || DOMAIN.matcher(n).find()
                || JDK_CLASS.matcher(n).find() || PROGRAM.matcher(n).find()) {
            return true;
        }
        for (Pattern p : WEBHOOKS_AND_PASTE_SITES) {
            if (p.matcher(n).find()) {
                return true;
            }
        }
        return SENSITIVE_PATHS.stream().anyMatch(n::contains) || PERSISTENCE_PATHS.stream().anyMatch(n::contains);
    }

    /** Shortened, with control characters escaped, for the report. */
    private static String printable(String s) {
        StringBuilder sb = new StringBuilder();
        for (char ch : s.toCharArray()) {
            if (sb.length() >= 120) {
                return sb + "...";
            }
            sb.append(ch < 0x20 || ch == 0x7f ? String.format("\\u%04x", (int) ch) : String.valueOf(ch));
        }
        return sb.toString();
    }

    private static List<Pattern> patterns(String... regexes) {
        List<Pattern> list = new ArrayList<>();
        for (String r : regexes) {
            list.add(Pattern.compile(r));
        }
        return list;
    }
}
