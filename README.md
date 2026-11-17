# CSCE465-Research-Project

Research project for the CSCE 465 final. The contributors on this team are Zachary Renkema and Cameron Farley.

The project is **modscanner**, a static scanner for Minecraft mod files. It reads a mod's `.jar` (or a `.zip` of a full download) without running it, looks for risky behavior in the compiled code, and prints a risk score with a plain-language reason for each finding.

## Build

You need a JDK, version 17 or newer. Maven does not need to be installed: the wrapper downloads it on first use.

```sh
cd modscanner
./mvnw package        # macOS and Linux
.\mvnw.cmd package    # Windows
```

This runs the tests and produces `modscanner/target/modscanner-0.1.0.jar`, a single runnable jar.

## Run

```sh
java -jar modscanner/target/modscanner-0.1.0.jar some-mod.jar
java -jar modscanner/target/modscanner-0.1.0.jar path/to/mods-folder        # every .jar/.zip, subfolders included
java -jar modscanner/target/modscanner-0.1.0.jar --json -o report.json path/to/mods-folder
```

| Option | Meaning |
|---|---|
| `--json` | JSON report with all evidence, the score breakdown, entrypoints, and the settings used |
| `-o <file>` | Write the report to a file |
| `-v`, `--verbose` | Text report with every finding, the score arithmetic, and the entrypoints |
| `--config <file>` | Override weights, pairs, or thresholds (see below) |
| `--print-config` | Print the settings in use |

Exit code: `0` nothing flagged, `1` at least one file flagged, `2` a file could not be fully scanned and nothing was flagged, `3` bad command line.

### Demo mods

Every build writes five synthetic demo mods to `modscanner/target/demo-mods/`: a staged loader, a token stealer, a persistence plugin, an update checker, and a clean mod. They contain the API calls and strings the rules look for, but no working code, so they are safe on any laptop:

```sh
java -jar modscanner/target/modscanner-0.1.0.jar modscanner/target/demo-mods
```

Never bring real malware samples onto a development or demo machine. They stay in the isolated analysis VM.

## Reading the report

```
Risk: HIGH (score 16)  ** FLAGGED **

What this mod can do:
  - This mod can load and run new code that is not inside the mod file, ... This happens as soon as the game loads the mod.
      com.coolcheats.Mod.<clinit>: java.net.URLClassLoader.<init>
Combinations that raise the score:
  + Can download code and then run it. (+3)
Files the scanner could not check (it cannot tell you what these do):
  - natives/helper.exe (Windows executable or DLL)
```

- **Risk** is LOW (score 0–2), MEDIUM (3–5) or HIGH (6 or more). Only HIGH counts as flagged.
- **What this mod can do** has one line per signal found, followed by the place it was found (`class.method: evidence`). "This happens as soon as the game loads the mod" means the evidence is in load-time code, which counts double.
- **Combinations** are pairs of signals that together suggest an attack.
- **Files the scanner could not check** are native libraries, programs, scripts, and unreadable classes. The scanner lists them but does not analyze them.

In the JSON report, every finding has `signal`, `archive` (with `!/` marking a nested JAR), `location` (class), `method`, `evidence` (the API call or string), `via` (`call`, `method_ref`, `reflection`, `string`, `class`, `file`), `line`, and `loadTime`. `scoreBreakdown` gives `weight`, `s`, and `points` for every signal.

## Scoring and changing the weights

```
R = Σ wᵢ·sᵢ + Σ bⱼ·cⱼ
```

`sᵢ` is 0 if signal i is absent, 1 if present, and 2 if present in load-time code. `cⱼ` is 1 when both signals of pair j are present anywhere in the download (nested JARs included), and adds `bⱼ`.

All of these numbers live in [`modscanner/src/main/resources/modscanner/default-config.json`](modscanner/src/main/resources/modscanner/default-config.json), which matches the paper. To try other values without editing the defaults, write a file with only the keys you want to change and pass it with `--config`:

```json
{ "weights": { "network_access": 2 }, "thresholds": { "high": 8 } }
```

Objects (`weights`, `thresholds`) merge key by key; lists (`pairs`) replace the default list. A misspelled signal name is an error.

| Signal | Weight | Detected by |
|---|---|---|
| `network_access` | 1 | Socket, `HttpClient`, `HttpURLConnection`, OkHttp, Apache HTTP, or Netty connect calls. `URL.openStream`/`openConnection` only when the class also has a web address or uses `HttpURLConnection`. A `URLClassLoader` next to a web address. |
| `native_code` | 1 | `System.load`/`loadLibrary`, JNA, the Foreign Function API, `native` methods, bundled `.dll`/`.so`/`.dylib`/`.exe` files (also recognized by content) |
| `obfuscated_code` | 1 | Half of 10+ classes with 1–2 letter names, 3+ names no compiler produces, class files hidden under other names, programs disguised as other files, unreadable class files |
| `encoded_strings` | 2 | Text decoded from Base64 or from byte/char arrays that names a URL, IP, domain, program, Java internal class, or a sensitive or persistence path |
| `runtime_class_loading` | 2 | `defineClass` (any owner), `URLClassLoader`, script engines, the Java agent class-rewriting API, classes that extend `ClassLoader` |
| `process_execution` | 2 | `Runtime.exec`, `ProcessBuilder` |
| `webhooks_or_paste_sites` | 3 | Discord webhooks and attachments, Telegram bot API, Slack hooks, ngrok, paste and file-drop sites |
| `sensitive_file_access` | 3 | Browser, Discord, launcher, and wallet login paths (Windows, macOS, Linux), and reading the Minecraft session token |
| `persistence_paths` | 3 | Windows Run keys, Startup folder, `schtasks`; macOS LaunchAgents, `launchctl`; Linux systemd, autostart, cron, shell rc files |
| `modifies_other_jars` | 3 | Writes ZIP/JAR files and also refers to `.jar` files or generates bytecode |

API rules also match method references (`Runtime::exec`). They also match reflection: a class name string together with a method name string in a class that uses reflection.

| Pair | Bonus | Source |
|---|---|---|
| network_access + runtime_class_loading | 3 | paper |
| sensitive_file_access + network_access | 3 | proposed |
| sensitive_file_access + webhooks_or_paste_sites | 3 | proposed |
| encoded_strings + runtime_class_loading | 3 | proposed |
| persistence_paths + process_execution | 3 | proposed |

**Load-time code** is the static initializers, constructors, and init methods of the entrypoint classes declared by the mod's metadata, plus everything reachable from them within the same JAR, up to `loadTimeCallDepth` (3) calls deep. Supported metadata:

- Fabric and Quilt
- Forge and NeoForge (`@Mod` classes and event subscribers)
- Legacy Forge (`@Mod.EventHandler` methods, coremods, and tweakers)
- Bukkit, Paper, and BungeeCord
- The manifest's `Main-Class` and agent attributes
- Mixin config plugins
- Mod-loader service files

## Project layout

All code is in `modscanner/src/main/java/modscanner/`:

| File | Role |
|---|---|
| `Main` | Command line |
| `Scanner` | Runs the pipeline and computes the score |
| `ArchiveReader`, `ModFile` | Read the file and nested JARs safely (size, ratio, entry, and nesting limits) |
| `ClassAnalyzer`, `ClassFacts`, `Strings` | Extract calls and strings, including decoded ones, from each class with ASM |
| `EntrypointParser`, `Entrypoint`, `LoadTime` | Find startup classes and mark load-time code |
| `Rules`, `Signal`, `Finding` | The detection rules |
| `ScanConfig`, `RiskLevel` | Scoring settings |
| `Report`, `ScanResult` | Text and JSON output |

The tests in `modscanner/src/test` build synthetic class files and JARs with ASM; no real mods or malware are needed.
