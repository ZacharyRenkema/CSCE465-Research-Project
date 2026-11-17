package modscanner;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.file.Path;

import static modscanner.Fixtures.cls;
import static modscanner.Fixtures.jar;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ArchiveReaderTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private ModFile read(byte[] bytes) throws IOException {
        return read(bytes, ArchiveReader.Limits.DEFAULT);
    }

    private ModFile read(byte[] bytes, ArchiveReader.Limits limits) throws IOException {
        Path p = Fixtures.write(tmp.getRoot().toPath(), "test.jar", bytes);
        return ArchiveReader.read(p, limits);
    }

    private static ModFile.NotableFile notable(ModFile mod, ModFile.FileKind kind) {
        for (ModFile.Archive a : mod.archives) {
            for (ModFile.NotableFile f : a.notableFiles) {
                if (f.kind() == kind) {
                    return f;
                }
            }
        }
        return null;
    }

    @Test
    public void readsClassesAndMetadata() throws IOException {
        ModFile mod = read(jar(
                "com/example/Mod.class", cls("com/example/Mod").bytes(),
                "fabric.mod.json", "{}",
                "assets/example/lang/en_us.json", "{}"));
        assertTrue(mod.complete);
        assertEquals(1, mod.archives.size());
        assertEquals(1, mod.classCount());
        assertTrue(mod.archives.get(0).metadata.containsKey("fabric.mod.json"));
        assertFalse("ordinary resources are not kept", mod.archives.get(0).metadata.containsKey("assets/example/lang/en_us.json"));
        assertEquals(64, mod.sha256.length());
    }

    @Test
    public void rejectsFileThatIsNotAnArchive() {
        try {
            read("this is a text file renamed to .jar".getBytes());
            fail("expected rejection");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("not a ZIP or JAR"));
        }
    }

    @Test
    public void rejectsOversizedFile() {
        ArchiveReader.Limits small = new ArchiveReader.Limits(100, 1 << 20, 1 << 20, 100, 4, 200);
        try {
            read(jar("a.txt", "x".repeat(10_000)), small);
            fail("expected rejection");
        } catch (IOException e) {
            assertTrue(e.getMessage().contains("larger than"));
        }
    }

    @Test
    public void stopsOnZipBomb() throws IOException {
        // 8 MB of zeros compresses to a few KB, far past a 50x ratio. The floor is 64 MB, so use
        // an absolute total limit to trigger it quickly as well.
        byte[] bomb = jar("zeros.bin", new byte[8 << 20]);
        ArchiveReader.Limits limits = new ArchiveReader.Limits(1 << 20, 64 << 20, 1 << 20, 100, 4, 50);
        ModFile mod = read(bomb, limits);
        assertFalse(mod.complete);
        assertTrue(mod.problems.get(0).contains("zip bomb"));
    }

    @Test
    public void stopsOnCompressionRatio() throws IOException {
        // Two 40 MB entries: each is under the 64 MB entry limit, together they pass the 64 MB floor.
        byte[] bomb = jar("a.bin", new byte[40 << 20], "b.bin", new byte[40 << 20]);
        ModFile mod = read(bomb);
        assertFalse(mod.complete);
        assertTrue(mod.problems.get(0).contains("times the file size"));
    }

    @Test
    public void readsNestedJars() throws IOException {
        byte[] inner = jar("lib/Inner.class", cls("lib/Inner").bytes());
        ModFile mod = read(jar(
                "com/example/Mod.class", cls("com/example/Mod").bytes(),
                "META-INF/jars/lib.jar", inner));
        assertEquals(2, mod.archives.size());
        assertEquals("test.jar!/META-INF/jars/lib.jar", mod.archives.get(1).path);
        assertEquals("lib/Inner", mod.archives.get(1).classes.get(0).name);
    }

    @Test
    public void stopsAtNestingLimit() throws IOException {
        byte[] level = jar("deep/Deep.class", cls("deep/Deep").bytes());
        for (int i = 0; i < 3; i++) {
            level = jar("nested" + i + ".jar", level);
        }
        ArchiveReader.Limits limits = new ArchiveReader.Limits(1 << 20, 1 << 20, 1 << 24, 100, 2, 200);
        ModFile mod = read(level, limits);
        assertEquals(3, mod.archives.size());
        assertEquals(ModFile.FileKind.TOO_DEEP, notable(mod, ModFile.FileKind.TOO_DEEP).kind());
        assertEquals(0, mod.classCount());
    }

    @Test
    public void corruptClassIsReportedNotThrown() throws IOException {
        byte[] good = cls("com/example/Good").bytes();
        byte[] corrupt = java.util.Arrays.copyOf(good, 20); // valid header, then cut off
        ModFile mod = read(jar(
                "com/example/Good.class", good,
                "com/example/Broken.class", corrupt,
                "com/example/NotAClass.class", "hello"));
        assertEquals(1, mod.classCount());
        int bad = 0;
        for (ModFile.NotableFile f : mod.archives.get(0).notableFiles) {
            if (f.kind() == ModFile.FileKind.BAD_CLASS) {
                bad++;
            }
        }
        assertEquals(2, bad);
    }

    @Test
    public void readsClassNewerThanAsmSupports() throws IOException {
        byte[] b = cls("com/example/Future").bytes();
        b[6] = 0;
        b[7] = 99; // a Java version that does not exist yet
        ModFile mod = read(jar("com/example/Future.class", b));
        assertEquals(String.valueOf(mod.archives.get(0).notableFiles), 1, mod.classCount());
    }

    @Test
    public void listsNativeFilesAndScripts() throws IOException {
        ModFile mod = read(jar(
                "natives/helper.dll", Fixtures.fakeWindowsExecutable(),
                "natives/libhelper.so", "not really elf",
                "run.bat", "echo hi"));
        assertEquals("Windows executable or DLL", notable(mod, ModFile.FileKind.NATIVE).detail());
        assertEquals("run.bat", notable(mod, ModFile.FileKind.SCRIPT).path());
    }

    @Test
    public void detectsExecutableWithFakeExtension() throws IOException {
        ModFile mod = read(jar("assets/icon.png", Fixtures.fakeWindowsExecutable()));
        ModFile.NotableFile f = notable(mod, ModFile.FileKind.DISGUISED_NATIVE);
        assertEquals("assets/icon.png", f.path());
    }

    @Test
    public void analyzesClassHiddenUnderOtherName() throws IOException {
        ModFile mod = read(jar("assets/data.bin", cls("com/example/Payload").bytes()));
        assertEquals(1, mod.classCount());
        assertEquals("assets/data.bin", notable(mod, ModFile.FileKind.HIDDEN_CLASS).path());
    }
}
