package modscanner;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Everything read from one scanned file: the top-level archive and every archive nested inside it.
 * Produced by {@link ArchiveReader}; the rules work only on this model, never on the raw file.
 */
final class ModFile {

    /** Files the scanner noticed but did not analyze as code, or that look out of place. */
    enum FileKind {
        /** A native library or program (.dll, .so, .dylib, .exe, ...). Listed, not analyzed. */
        NATIVE,
        /** A native program hiding under another extension, e.g. an .exe named icon.png. */
        DISGUISED_NATIVE,
        /** A script (.bat, .ps1, .sh, ...). Listed, not analyzed. */
        SCRIPT,
        /** A .class entry that ASM could not parse. */
        BAD_CLASS,
        /** A class file stored under a name that does not end in .class. It is analyzed anyway. */
        HIDDEN_CLASS,
        /** A nested archive deeper than the nesting limit. Not opened. */
        TOO_DEEP
    }

    record NotableFile(String path, FileKind kind, long size, String detail) {
    }

    /** One archive: the top-level file or a nested JAR. */
    static final class Archive {
        /** "mod.jar", or "mod.jar!/META-INF/jars/lib.jar" for a nested JAR. */
        final String path;
        final int depth;
        final List<ClassFacts> classes = new ArrayList<>();
        /** Small metadata files (fabric.mod.json, plugin.yml, MANIFEST.MF, ...) by entry name. */
        final Map<String, byte[]> metadata = new LinkedHashMap<>();
        final List<NotableFile> notableFiles = new ArrayList<>();

        Archive(String path, int depth) {
            this.path = path;
            this.depth = depth;
        }
    }

    final String name;
    final long size;
    final String sha256;
    final List<Archive> archives = new ArrayList<>();
    /** False if reading stopped early (a limit was hit or an archive was malformed). */
    boolean complete = true;
    final List<String> problems = new ArrayList<>();

    ModFile(String name, long size, String sha256) {
        this.name = name;
        this.size = size;
        this.sha256 = sha256;
    }

    int classCount() {
        int n = 0;
        for (Archive a : archives) {
            n += a.classes.size();
        }
        return n;
    }
}
