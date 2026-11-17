# CSCE 465 Research Project: modscanner

This repo holds the code for a CSCE 465 (computer security) final project at Texas A&M by Zac Renkema and Cameron Farley. The paper is "Static Analysis and Detection of Malicious Game Mods". Both of us use Claude in this repo, so this file is the shared source of truth for what we are building and the rules we agreed on. If a request conflicts with this file, point out the conflict before going ahead, because the other partner relies on it.

## What we are building

`modscanner` is a static scanner for Minecraft mod JAR files. It reads a mod without running it, looks for risky capabilities in the bytecode, and prints a risk score with a plain-language reason for each finding, written for players with no security background. We will run it on a small labeled dataset (three malware families, two benign mods) and compare it with baseline tools such as jNeedle and PluginGuard.

The paper also has a case study of "crossover" mods such as SkyCraft, which pair a Java mod with native code. The scanner lists native files but does not analyze them. That gap is itself a finding of the paper, so do not hide it.

## Rules that must hold

- **No real malware on a development machine.** Samples stay in password-protected archives and are opened only in the isolated Windows VM. Do not download, unpack, or commit malware here. Test fixtures are synthetic: tiny classes and JARs built in the tests with ASM's `ClassWriter`, containing the API calls and strings a rule looks for, with no working payload. Downloading popular benign mods from Modrinth for false-positive checks is fine; keep them out of git (`samples/` and `*.jar` are ignored).
- **The scanner never executes its input.** Archives are read as bytes in memory. No class loading, no reflection on scanned classes, and nothing is written to disk under names taken from the archive. Treat every input as hostile: zip bombs, deep nesting, corrupt class files.
- **Rules describe capabilities, not signatures.** We test on a malware family held out while the rules are written, so a rule must describe general behavior and never a specific hash, domain, or class name from a known family. Do not look at or tune against the held-out family.
- **The paper's numbers change only if we both agree.** The weights, the pair bonus, and the thresholds below are stated in the paper. They live in `modscanner/src/main/resources/modscanner/default-config.json`. If a value looks wrong, say so; do not quietly change it.
- **Report limitations candidly.** Anything the scanner misses or detects weakly goes in the paper's limitations section. Never describe a result as measured unless it was actually run.
- **Keep the code simple.** This is a student research prototype. Prefer a few plain classes and straightforward rules over clever abstractions. Add a heuristic only when it earns its place, and explain it in a comment.

## Design from the paper

Pipeline: input file, then type and size checks, then unpack (including nested JARs), then three extractions (metadata and entrypoints, bytecode via ASM, file inventory), then signal rules, risk score, and report.

| Signal (config id) | Why it matters | Weight |
|---|---|---|
| Network access (`network_access`) | Can download files or send data out | 1 |
| Native code (`native_code`) | Runs code the scanner cannot read | 1 |
| Obfuscated code (`obfuscated_code`) | Can hide what the code does | 1 |
| Encoded URLs or strings (`encoded_strings`) | Can hide a download or upload site | 2 |
| Runtime class loading (`runtime_class_loading`) | Can run code not present in the JAR | 2 |
| Process execution (`process_execution`) | Can start programs outside the game | 2 |
| Webhooks or paste sites (`webhooks_or_paste_sites`) | Common ways to send out data or fetch payloads | 3 |
| Sensitive file access (`sensitive_file_access`) | Can read browser, Discord, or launcher logins | 3 |
| Persistence paths (`persistence_paths`) | Can make code run again after a restart | 3 |
| Modifies other JARs (`modifies_other_jars`) | Can spread to other mods on the machine | 3 |

Risk score: `R = Σ wᵢ·sᵢ + Σ bⱼ·cⱼ`

- `sᵢ` is 0 if signal i is absent, 1 if present, and 2 if present in load-time code. A signal counts once however often it occurs.
- Load-time code is the static initializers, constructors, and init methods of entrypoint classes declared in mod metadata (`fabric.mod.json`, `quilt.mod.json`, Forge/NeoForge `mods.toml` with `@Mod` classes, `plugin.yml`, `paper-plugin.yml`, `bungee.yml`, and the manifest's `Main-Class` and agent attributes), plus a shallow call graph inside the JAR from those methods.
- `cⱼ` is 1 when a suspicious pair of signals appears together, and each pair adds `bⱼ = 3`. The paper names one pair, network access with runtime class loading. Any other pairs are our additions, are marked `"source": "proposed"` in the config, and must be listed in the README so the paper can cite them.
- Score 0–2 is low, 3–5 is medium, 6 or more is high. Only high counts as flagged.

Output: the default text report shows the risk level first, then one plain-language line per finding, then the files the scanner could not check. `--json` carries the full evidence (signal, class, method, triggering API or string, load-time or not, nested JAR) for the paper's error analysis. A directory can be scanned in one run. The exit code says whether anything was flagged.

## Build and layout

- `modscanner/` is a Maven project (Java 17 target, ASM tree API, Gson, JUnit 4). The shade plugin builds a single runnable jar.
- Maven is not installed system-wide; use the wrapper. From `modscanner/`: `.\mvnw.cmd package` on Windows, `./mvnw package` on macOS and Linux. The first run downloads Maven. The jar is `modscanner/target/modscanner-0.1.0.jar`.
- It must run on macOS as well as Windows, because the demo may be on a Mac. Use `Path` APIs, never hard-coded path separators or Windows-only commands. `.gitattributes` keeps `mvnw` at LF line endings and git stores it as executable; keep both. Detection rules must cover macOS and Linux targets too (Mach-O binaries, LaunchAgents, systemd), not just Windows.
- Source files (all in `modscanner/src/main/java/modscanner/`): `ArchiveReader` reads the file and nested JARs into a `ModFile` under zip-bomb limits; `ClassAnalyzer` turns each class into `ClassFacts` (calls, strings, decoded strings); `Strings` has the decoding helpers; `Rules` holds every detection rule (API tables and path/URL patterns) and produces `Finding`s for each `Signal`; `EntrypointParser` reads loader metadata into `Entrypoint`s; `LoadTime` marks methods reachable from entrypoints (call depth from config); `Scanner` runs the whole pipeline and computes the score; `ScanConfig` loads `default-config.json` plus an optional override file; `Report` formats text and JSON; `Main` is the command line. The README documents usage and every rule. Pairs are counted when both signals appear anywhere in the download, nested JARs included. New detection logic belongs in `Rules`, with a trigger test and a near-miss test in `RulesTest`. Tests build synthetic fixtures with `Fixtures` in `src/test`.
- `target/` and downloaded mods are not committed.
- The paper is LaTeX and is not kept in this repo. When a code change makes the paper inaccurate (a new pair, a changed detection method, a new limitation), say so in your summary so we can update it.

## Implementation plan and status

We are building this in small steps and committing after each one. Update this list as steps land.

1. [x] Project setup: Maven wrapper, `.gitignore`, dependencies, this file.
2. [x] Reading input: archive checks, zip-bomb limits, nested JARs, file inventory, class analysis (calls, strings, decoded strings).
3. [x] The ten signal rules, each with a test that triggers it and a near-miss test that does not.
4. [x] Entrypoints for each loader, load-time marking, risk score, pairs, thresholds.
5. [x] Text and JSON reports, command line, directory mode, exit codes, README, end-to-end run on a real benign mod.

## Benign false-positive check (2026-11-17)

17 popular Modrinth mods were scanned (kept in `samples/benign/`, not in git; rerun with `java -jar modscanner/target/modscanner-0.1.0.jar samples/benign`). Four rule bugs found this way were fixed, each with a near-miss test: `package-info` counted as an impossible name, Java keywords used as Kotlin names counted as obfuscation, `URL.openStream` on bundled resources counted as network access, and the word "CRONTAB" counted as persistence.

Five stay HIGH because they really have the behavior: AuthMe (account switcher: reads the session token and logs in over the network), Essential (downloads and runs its own updates, reads the token, bundles natives), LuckPerms (downloads libraries and loads them in its own class loader), WorldEdit (bundled Rhino JavaScript engine defines classes, plus network), and Sodium (runs `xdg-open` and `lspci` at startup and generates classes). These are expected "hard benign" false positives for the paper. Do not add allow-lists or per-mod exceptions to make them pass; that would be a signature, and it would bias the evaluation.

## Demo

Every build writes synthetic demo mods to `modscanner/target/demo-mods/` (see `DemoModsTest`). Use those for demos, on Windows or macOS. Never real malware.

## Working together

Keep changes small enough to review. Explain any decision made where the design above was silent, in the commit message or summary. Do not commit or push unless asked.
