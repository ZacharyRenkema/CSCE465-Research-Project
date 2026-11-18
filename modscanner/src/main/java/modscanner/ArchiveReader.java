package modscanner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Reads a mod file into a {@link ModFile}. Every entry is read into memory as bytes. Nothing is
 * extracted to disk and nothing is loaded or run. One set of limits covers the whole file, nested
 * archives included, which is what stops zip bombs.
 */
final class ArchiveReader {

    /** Size limits. The defaults are generous for real mods (the largest are around 100 MB). */
    record Limits(long maxInputBytes, long maxEntryBytes, long maxTotalBytes, int maxEntries, int maxDepth,
                  int maxCompressionRatio) {
        static final Limits DEFAULT = new Limits(256L << 20, 64L << 20, 1L << 30, 200_000, 4, 200);
    }

    /** Thrown when a limit is hit. The scan stops and the result is marked incomplete. */
    static final class LimitExceeded extends IOException {
        LimitExceeded(String message) {
            super(message);
        }
    }

    /** Total decompressed bytes may always reach this much, whatever the compression ratio. */
    private static final long RATIO_FLOOR_BYTES = 64L << 20;

    private static final Set<String> NATIVE_EXTENSIONS =
            Set.of("dll", "so", "dylib", "jnilib", "exe", "asi", "sys", "node", "scr");
    private static final Set<String> SCRIPT_EXTENSIONS =
            Set.of("bat", "cmd", "ps1", "vbs", "vbe", "wsf", "sh", "command", "hta");

    private final Limits limits;
    private final long inputSize;
    private long totalBytes;
    private int entryCount;

    private ArchiveReader(Limits limits, long inputSize) {
        this.limits = limits;
        this.inputSize = inputSize;
    }

    /**
     * @throws IOException if the file cannot be read, is too large, or is not a ZIP/JAR archive
     */
    static ModFile read(Path file, Limits limits) throws IOException {
        long size = Files.size(file);
        if (size > limits.maxInputBytes()) {
            throw new IOException("file is " + size + " bytes, larger than the " + limits.maxInputBytes() + " byte limit");
        }
        byte[] data = Files.readAllBytes(file);
        if (!isZip(data)) {
            throw new IOException("not a ZIP or JAR archive (checked by file content, not extension)");
        }
        ModFile mod = new ModFile(file.getFileName().toString(), size, sha256(data));
        ArchiveReader reader = new ArchiveReader(limits, size);
        try {
            reader.readArchive(mod, mod.name, data, 0);
        } catch (LimitExceeded e) {
            mod.complete = false;
            mod.problems.add("scan stopped early: " + e.getMessage());
        }
        return mod;
    }

    private void readArchive(ModFile mod, String path, byte[] data, int depth) throws LimitExceeded {
        ModFile.Archive archive = new ModFile.Archive(path, depth);
        mod.archives.add(archive);
        List<String> nestedNames = new ArrayList<>();
        List<byte[]> nestedData = new ArrayList<>();

        // ZipInputStream reads the local entry headers in order. Mod loaders read the central
        // directory instead; the two only differ for deliberately malformed archives.
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.isDirectory()) {
                    continue;
                }
                if (++entryCount > limits.maxEntries()) {
                    throw new LimitExceeded("more than " + limits.maxEntries() + " entries (possible zip bomb)");
                }
                byte[] bytes = readEntry(zis);
                if (isZip(bytes)) {
                    nestedNames.add(e.getName());
                    nestedData.add(bytes);
                } else {
                    classify(archive, e.getName(), bytes);
                }
            }
        } catch (LimitExceeded e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            mod.complete = false;
            mod.problems.add(path + ": archive could not be fully read (" + e.getMessage() + ")");
        }

        for (int i = 0; i < nestedNames.size(); i++) {
            String name = nestedNames.get(i);
            if (depth + 1 > limits.maxDepth()) {
                archive.notableFiles.add(new ModFile.NotableFile(name, ModFile.FileKind.TOO_DEEP,
                        nestedData.get(i).length, "archive nested more than " + limits.maxDepth() + " levels deep"));
            } else {
                readArchive(mod, path + "!/" + name, nestedData.get(i), depth + 1);
            }
        }
    }

    private byte[] readEntry(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[64 * 1024];
        long entryBytes = 0;
        int n;
        while ((n = in.read(buf)) > 0) {
            entryBytes += n;
            totalBytes += n;
            if (entryBytes > limits.maxEntryBytes()) {
                throw new LimitExceeded("an entry is larger than " + limits.maxEntryBytes() + " bytes (possible zip bomb)");
            }
            if (totalBytes > limits.maxTotalBytes()) {
                throw new LimitExceeded("more than " + limits.maxTotalBytes() + " bytes decompressed (possible zip bomb)");
            }
            if (totalBytes > Math.max(RATIO_FLOOR_BYTES, inputSize * limits.maxCompressionRatio())) {
                throw new LimitExceeded("decompressed data is over " + limits.maxCompressionRatio()
                        + " times the file size (possible zip bomb)");
            }
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    /** Sorts one non-archive entry into classes, metadata, or notable files. */
    private static void classify(ModFile.Archive archive, String name, byte[] bytes) {
        String ext = extension(name);
        boolean nativeMagic = hasNativeMagic(bytes);

        if (ext.equals("class") || (!nativeMagic && ClassAnalyzer.looksLikeClassFile(bytes))) {
            boolean hidden = !ext.equals("class");
            ClassFacts facts = null;
            String error = "not a valid class file";
            if (ClassAnalyzer.looksLikeClassFile(bytes)) {
                try {
                    facts = ClassAnalyzer.analyze(bytes, name);
                } catch (RuntimeException e) {
                    error = "ASM could not parse it: " + e;
                }
            }
            if (facts == null) {
                archive.notableFiles.add(new ModFile.NotableFile(name, ModFile.FileKind.BAD_CLASS, bytes.length, error));
                return;
            }
            archive.classes.add(facts);
            if (hidden) {
                archive.notableFiles.add(new ModFile.NotableFile(name, ModFile.FileKind.HIDDEN_CLASS, bytes.length,
                        "class file " + facts.name + " stored under a non-.class name"));
            }
        } else if (NATIVE_EXTENSIONS.contains(ext)) {
            archive.notableFiles.add(new ModFile.NotableFile(name, ModFile.FileKind.NATIVE, bytes.length,
                    nativeMagic ? nativeFormat(bytes) : "native file extension"));
        } else if (nativeMagic) {
            archive.notableFiles.add(new ModFile.NotableFile(name, ModFile.FileKind.DISGUISED_NATIVE, bytes.length,
                    nativeFormat(bytes) + " with a ." + ext + " extension"));
        } else if (SCRIPT_EXTENSIONS.contains(ext)) {
            archive.notableFiles.add(new ModFile.NotableFile(name, ModFile.FileKind.SCRIPT, bytes.length, "script"));
        } else if (isMetadataName(name) && bytes.length <= 1 << 20) {
            archive.metadata.put(name, bytes);
        }
    }

    static boolean isZip(byte[] b) {
        return b.length >= 4 && b[0] == 'P' && b[1] == 'K'
                && ((b[2] == 3 && b[3] == 4) || (b[2] == 5 && b[3] == 6));
    }

    private static boolean hasNativeMagic(byte[] b) {
        return nativeFormat(b) != null;
    }

    /** Windows PE, Linux ELF, or macOS Mach-O, recognized by their first bytes; null otherwise. */
    private static String nativeFormat(byte[] b) {
        if (b.length < 8) {
            return null;
        }
        if (b[0] == 'M' && b[1] == 'Z') {
            return "Windows executable or DLL";
        }
        if (b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
            return "Linux ELF binary";
        }
        int magic = ClassAnalyzer.readInt(b, 0);
        if (magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCEFAEDFE || magic == 0xCFFAEDFE) {
            return "macOS Mach-O binary";
        }
        // Universal Mach-O binaries share the 0xCAFEBABE magic with class files. The next field is
        // a small architecture count for Mach-O but a class file version (45 or more) for Java.
        if (magic == 0xCAFEBABE && ClassAnalyzer.readInt(b, 4) < 45) {
            return "macOS universal binary";
        }
        return null;
    }

    private static String extension(String name) {
        int slash = name.lastIndexOf('/');
        int dot = name.lastIndexOf('.');
        return dot > slash ? name.substring(dot + 1).toLowerCase(Locale.ROOT) : "";
    }

    /** Files that say which classes a mod loader runs; kept for the entrypoint step. */
    static boolean isMetadataName(String name) {
        return name.equals("fabric.mod.json") || name.equals("quilt.mod.json")
                || name.equals("META-INF/MANIFEST.MF") || name.equals("META-INF/mods.toml")
                || name.equals("META-INF/neoforge.mods.toml") || name.equals("mcmod.info")
                || name.equals("plugin.yml") || name.equals("paper-plugin.yml") || name.equals("bungee.yml")
                || name.startsWith("META-INF/services/")
                || (name.endsWith(".json") && name.toLowerCase(Locale.ROOT).contains("mixin"));
    }

    private static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
