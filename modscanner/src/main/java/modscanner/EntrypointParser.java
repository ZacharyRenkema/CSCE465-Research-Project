package modscanner;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Finds the classes each mod loader runs at startup, from the metadata files in one archive. */
final class EntrypointParser {

    private EntrypointParser() {
    }

    /** Fabric and Quilt entrypoint keys that run during startup, and the method each one calls. */
    private static final Map<String, String> STARTUP_KEYS = Map.of(
            "main", "onInitialize", "client", "onInitializeClient", "server", "onInitializeServer",
            "preLaunch", "onPreLaunch",
            "init", "onInitialize", "client_init", "onInitializeClient", "server_init", "onInitializeServer",
            "pre_launch", "onPreLaunch");

    private static final Map<String, String> MOD_ANNOTATIONS = Map.of(
            "Lnet/minecraftforge/fml/common/Mod;", "forge",
            "Lnet/neoforged/fml/common/Mod;", "neoforge",
            "Lcpw/mods/fml/common/Mod;", "forge-legacy");

    /** Classes with these annotations are loaded at startup so their event handlers can be registered. */
    private static final Map<String, String> SUBSCRIBER_ANNOTATIONS = Map.of(
            "Lnet/minecraftforge/fml/common/Mod$EventBusSubscriber;", "forge",
            "Lnet/neoforged/fml/common/Mod$EventBusSubscriber;", "neoforge",
            "Lnet/neoforged/fml/common/EventBusSubscriber;", "neoforge");

    /** Legacy Forge (1.7-1.12) calls methods with this annotation during startup (preInit, init, ...). */
    private static final List<String> EVENT_HANDLER_ANNOTATIONS = List.of(
            "Lnet/minecraftforge/fml/common/Mod$EventHandler;", "Lcpw/mods/fml/common/Mod$EventHandler;");

    /** META-INF/services interfaces that the mod loaders themselves load at startup. */
    private static final List<String> LOADER_SERVICES = List.of(
            "cpw.mods.modlauncher.", "net.minecraftforge.forgespi.", "net.minecraftforge.fml.",
            "net.neoforged.neoforgespi.", "net.neoforged.fml.");

    private static final Pattern YAML_ENTRY = Pattern.compile(
            "(?m)^(main|bootstrapper|loader)\\s*:\\s*[\"']?([A-Za-z0-9_.$]+)[\"']?\\s*(?:#.*)?$");

    /** Parses one archive. Problems with malformed metadata are added to {@code notes}. */
    static List<Entrypoint> parse(ModFile.Archive archive, List<String> loaders, List<String> notes) {
        List<Entrypoint> out = new ArrayList<>();
        List<String> mixinConfigs = new ArrayList<>();
        Map<String, byte[]> meta = archive.metadata;
        String path = archive.path;

        // Fabric and Quilt: entrypoints listed in JSON, e.g. "main": ["com.example.Mod"].
        JsonObject fabric = json(meta, "fabric.mod.json", notes);
        if (fabric != null) {
            add(loaders, "fabric");
            readEntrypoints(path, "fabric", "fabric.mod.json", fabric.get("entrypoints"), out);
            addMixinConfigs(fabric.get("mixins"), mixinConfigs);
        }
        JsonObject quilt = json(meta, "quilt.mod.json", notes);
        if (quilt != null) {
            add(loaders, "quilt");
            if (quilt.get("quilt_loader") instanceof JsonObject ql) {
                readEntrypoints(path, "quilt", "quilt.mod.json", ql.get("entrypoints"), out);
            }
            addMixinConfigs(quilt.get("mixin"), mixinConfigs);
        }

        // Forge and NeoForge: mods.toml says it is a Forge mod; the @Mod annotation marks the class.
        if (meta.containsKey("META-INF/mods.toml")) {
            add(loaders, "forge");
        }
        if (meta.containsKey("META-INF/neoforge.mods.toml")) {
            add(loaders, "neoforge");
        }
        for (ClassFacts c : archive.classes) {
            for (String ann : c.annotations) {
                String loader = MOD_ANNOTATIONS.get(ann);
                if (loader != null) {
                    if (meta.containsKey("mcmod.info")) {
                        loader = "forge-legacy";
                    }
                    add(loaders, loader);
                    List<String> methods = new ArrayList<>();
                    for (ClassFacts.Method m : c.methods) {
                        if (m.annotations.stream().anyMatch(EVENT_HANDLER_ANNOTATIONS::contains)) {
                            methods.add(m.name);
                        }
                    }
                    out.add(new Entrypoint(path, loader, c.dottedName(), methods, "@Mod annotation"));
                }
                if (SUBSCRIBER_ANNOTATIONS.containsKey(ann)) {
                    out.add(new Entrypoint(path, SUBSCRIBER_ANNOTATIONS.get(ann), c.dottedName(), List.of(),
                            "@EventBusSubscriber annotation"));
                }
            }
        }

        // Bukkit, Paper, and BungeeCord plugins: "main: com.example.Plugin" in YAML.
        readYaml(path, meta, "plugin.yml", "bukkit", loaders, out);
        readYaml(path, meta, "paper-plugin.yml", "paper", loaders, out);
        readYaml(path, meta, "bungee.yml", "bungeecord", loaders, out);

        readManifest(path, meta, loaders, mixinConfigs, notes, out);
        readServices(path, meta, loaders, out);

        // Mixin configs can name a plugin class that runs before the game itself starts.
        for (String config : mixinConfigs) {
            JsonObject mixin = json(meta, config, notes);
            JsonElement plugin = mixin == null ? null : mixin.get("plugin");
            if (plugin != null && plugin.isJsonPrimitive()) {
                out.add(new Entrypoint(path, "mixin-plugin", plugin.getAsString(), List.of("*"), config + " plugin"));
            }
        }
        return out;
    }

    private static void readEntrypoints(String path, String loader, String file, JsonElement entrypoints,
                                        List<Entrypoint> out) {
        if (!(entrypoints instanceof JsonObject eps)) {
            return;
        }
        for (Map.Entry<String, JsonElement> e : eps.entrySet()) {
            // Other keys (modmenu, rei, jei, ...) only run when another mod asks for them.
            String startupMethod = STARTUP_KEYS.get(e.getKey());
            if (startupMethod == null) {
                continue;
            }
            for (JsonElement el : list(e.getValue())) {
                String value = el.isJsonPrimitive() ? el.getAsString()
                        : el instanceof JsonObject o && o.has("value") ? o.get("value").getAsString() : null;
                if (value == null || value.isBlank()) {
                    continue;
                }
                // "com.example.Mod::init" names a method (or field) instead of the default.
                List<String> methods = new ArrayList<>(List.of(startupMethod));
                int sep = value.indexOf("::");
                if (sep >= 0) {
                    methods.add(value.substring(sep + 2).trim());
                    value = value.substring(0, sep);
                }
                out.add(new Entrypoint(path, loader, value.trim(), methods, file + " entrypoints." + e.getKey()));
            }
        }
    }

    private static void addMixinConfigs(JsonElement el, List<String> out) {
        for (JsonElement m : list(el)) {
            if (m.isJsonPrimitive()) {
                out.add(m.getAsString());
            } else if (m instanceof JsonObject o && o.has("config")) {
                out.add(o.get("config").getAsString());
            }
        }
    }

    private static void readYaml(String path, Map<String, byte[]> meta, String file, String loader,
                                 List<String> loaders, List<Entrypoint> out) {
        byte[] raw = meta.get(file);
        if (raw == null) {
            return;
        }
        add(loaders, loader);
        Matcher m = YAML_ENTRY.matcher(new String(raw, StandardCharsets.UTF_8));
        while (m.find()) {
            List<String> methods = switch (m.group(1)) {
                case "bootstrapper" -> List.of("bootstrap");
                case "loader" -> List.of("classloader");
                default -> List.of("onLoad", "onEnable");
            };
            out.add(new Entrypoint(path, loader, m.group(2), methods, file + " " + m.group(1)));
        }
    }

    private static void readManifest(String path, Map<String, byte[]> meta, List<String> loaders,
                                     List<String> mixinConfigs, List<String> notes, List<Entrypoint> out) {
        byte[] raw = meta.get("META-INF/MANIFEST.MF");
        if (raw == null) {
            return;
        }
        Attributes a;
        try {
            a = new Manifest(new ByteArrayInputStream(raw)).getMainAttributes();
        } catch (IOException | RuntimeException e) {
            notes.add(path + ": MANIFEST.MF could not be parsed");
            return;
        }
        // Main-Class runs if the player double-clicks the JAR, which fake "installers" rely on.
        manifestEntry(path, a, "Main-Class", "java-main", List.of("main"), loaders, out);
        manifestEntry(path, a, "Premain-Class", "java-agent", List.of("premain"), loaders, out);
        manifestEntry(path, a, "Agent-Class", "java-agent", List.of("agentmain"), loaders, out);
        manifestEntry(path, a, "Launcher-Agent-Class", "java-agent", List.of("agentmain"), loaders, out);
        // Legacy Forge coremods and LaunchWrapper tweakers run before the game, so every method counts.
        manifestEntry(path, a, "FMLCorePlugin", "forge-coremod", List.of("*"), loaders, out);
        manifestEntry(path, a, "TweakClass", "launchwrapper", List.of("*"), loaders, out);
        String mixins = a.getValue("MixinConfigs");
        if (mixins != null) {
            for (String m : mixins.split(",")) {
                if (!m.isBlank()) {
                    mixinConfigs.add(m.trim());
                }
            }
        }
    }

    private static void manifestEntry(String path, Attributes a, String key, String loader, List<String> methods,
                                      List<String> loaders, List<Entrypoint> out) {
        String v = a.getValue(key);
        if (v != null && !v.isBlank()) {
            add(loaders, loader);
            out.add(new Entrypoint(path, loader, v.trim(), methods, "MANIFEST.MF " + key));
        }
    }

    private static void readServices(String path, Map<String, byte[]> meta, List<String> loaders,
                                     List<Entrypoint> out) {
        for (Map.Entry<String, byte[]> e : meta.entrySet()) {
            String iface = e.getKey().substring(e.getKey().lastIndexOf('/') + 1);
            if (!e.getKey().startsWith("META-INF/services/") || LOADER_SERVICES.stream().noneMatch(iface::startsWith)) {
                continue;
            }
            for (String line : new String(e.getValue(), StandardCharsets.UTF_8).split("\\R")) {
                String cls = line.replaceAll("#.*", "").trim();
                if (!cls.isEmpty()) {
                    add(loaders, "loader-service");
                    out.add(new Entrypoint(path, "loader-service", cls, List.of("*"), e.getKey()));
                }
            }
        }
    }

    private static JsonObject json(Map<String, byte[]> meta, String name, List<String> notes) {
        byte[] raw = meta.get(name);
        if (raw == null) {
            return null;
        }
        try {
            JsonReader reader = new JsonReader(new StringReader(new String(raw, StandardCharsets.UTF_8)));
            reader.setStrictness(Strictness.LENIENT); // fabric.mod.json files sometimes contain comments
            JsonElement el = JsonParser.parseReader(reader);
            if (el instanceof JsonObject o) {
                return o;
            }
        } catch (RuntimeException e) {
            // fall through to the note
        }
        notes.add(name + " could not be parsed as JSON");
        return null;
    }

    private static List<JsonElement> list(JsonElement el) {
        List<JsonElement> out = new ArrayList<>();
        if (el instanceof JsonArray arr) {
            arr.forEach(out::add);
        } else if (el != null && !el.isJsonNull()) {
            out.add(el);
        }
        return out;
    }

    private static void add(List<String> loaders, String loader) {
        if (!loaders.contains(loader)) {
            loaders.add(loader);
        }
    }
}
