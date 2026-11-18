package modscanner;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

/** Command line entry point. See {@link #USAGE}. */
public final class Main {

    /** Exit codes. "Flagged" wins over "error" when a directory has both. */
    static final int EXIT_CLEAN = 0;
    static final int EXIT_FLAGGED = 1;
    static final int EXIT_ERROR = 2;
    static final int EXIT_USAGE = 3;

    private static final String USAGE = """
            Usage: java -jar modscanner.jar [options] <file or folder>...

            Scans Minecraft mod files (.jar or .zip) without running them and reports how risky they look.
            A folder is scanned for .jar and .zip files, including subfolders.

            Options:
              --json            Print a JSON report with all evidence (for analysis).
              -o <file>         Write the report to a file instead of the screen.
              -v, --verbose     Show every piece of evidence, the score breakdown, and entrypoints.
              --config <file>   Override weights, pairs, or thresholds (JSON; only the keys you change).
              --print-config    Print the settings in use and exit.
              -h, --help        Show this help.

            Exit code: 0 nothing flagged, 1 at least one file flagged, 2 a file could not be fully
            scanned (and nothing was flagged), 3 bad command line.
            """;

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        boolean json = false;
        boolean verbose = false;
        boolean printConfig = false;
        Path configFile = null;
        Path outputFile = null;
        List<Path> inputs = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "-h", "--help" -> {
                    out.print(USAGE);
                    return EXIT_CLEAN;
                }
                case "--json" -> json = true;
                case "-v", "--verbose" -> verbose = true;
                case "--print-config" -> printConfig = true;
                case "--config", "-o" -> {
                    if (i + 1 >= args.length) {
                        err.println(a + " needs a file name");
                        return EXIT_USAGE;
                    }
                    Path p = Paths.get(args[++i]);
                    if (a.equals("--config")) {
                        configFile = p;
                    } else {
                        outputFile = p;
                    }
                }
                default -> {
                    if (a.startsWith("-")) {
                        err.println("Unknown option " + a + "\n\n" + USAGE);
                        return EXIT_USAGE;
                    }
                    inputs.add(Paths.get(a));
                }
            }
        }

        ScanConfig config;
        try {
            config = configFile == null ? ScanConfig.defaults() : ScanConfig.load(configFile);
        } catch (IOException | RuntimeException e) {
            err.println("Could not read config " + configFile + ": " + e.getMessage());
            return EXIT_USAGE;
        }
        if (printConfig) {
            out.println(config.toJson());
            return EXIT_CLEAN;
        }
        if (inputs.isEmpty()) {
            err.print(USAGE);
            return EXIT_USAGE;
        }

        List<Path> files = new ArrayList<>();
        for (Path p : inputs) {
            if (Files.isDirectory(p)) {
                try (Stream<Path> walk = Files.walk(p)) {
                    walk.filter(Files::isRegularFile).filter(Main::isModFileName).sorted().forEach(files::add);
                } catch (IOException e) {
                    err.println("Could not read folder " + p + ": " + e.getMessage());
                    return EXIT_ERROR;
                }
            } else if (Files.isRegularFile(p)) {
                files.add(p); // checked by content, so any extension is accepted here
            } else {
                err.println("No such file or folder: " + p);
                return EXIT_USAGE;
            }
        }

        Scanner scanner = new Scanner(config);
        List<ScanResult> results = new ArrayList<>();
        StringBuilder text = new StringBuilder();
        for (Path f : files) {
            ScanResult r = scanner.scan(f);
            results.add(r);
            if (!json) {
                text.append(Report.text(r, verbose)).append("\n");
            }
        }
        if (!json && files.size() > 1) {
            text.append(Report.summary(results));
        }
        if (!json && files.isEmpty()) {
            text.append("No .jar or .zip files found.\n");
        }
        String report = json ? Report.json(results, config) + "\n" : text.toString();

        if (outputFile != null) {
            try {
                Files.writeString(outputFile, report, StandardCharsets.UTF_8);
            } catch (IOException e) {
                err.println("Could not write " + outputFile + ": " + e.getMessage());
                return EXIT_ERROR;
            }
        } else {
            out.print(report);
        }

        boolean anyFlagged = results.stream().anyMatch(r -> r.flagged);
        boolean anyIncomplete = results.stream().anyMatch(r -> !r.complete);
        return anyFlagged ? EXIT_FLAGGED : anyIncomplete ? EXIT_ERROR : EXIT_CLEAN;
    }

    private static boolean isModFileName(Path p) {
        String n = p.getFileName().toString().toLowerCase(Locale.ROOT);
        return n.endsWith(".jar") || n.endsWith(".zip");
    }
}
