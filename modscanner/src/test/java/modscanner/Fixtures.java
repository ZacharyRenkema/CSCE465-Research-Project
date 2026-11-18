package modscanner;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Builds synthetic class files and JARs for tests. The classes contain the instructions a rule
 * looks for (for example a call to Runtime.exec) but are never loaded or run, and have no payload.
 */
final class Fixtures {

    private Fixtures() {
    }

    /** Fluent builder for a class file. Bytecode does not have to verify: the scanner only parses it. */
    static final class ClassBuilder {
        private final ClassWriter cw = new ClassWriter(0);

        ClassBuilder(String name) {
            this(name, "java/lang/Object");
        }

        ClassBuilder(String name, String superName, String... interfaces) {
            cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, name, null, superName, interfaces.length == 0 ? null : interfaces);
        }

        ClassBuilder annotation(String desc) {
            cw.visitAnnotation(desc, true).visitEnd();
            return this;
        }

        ClassBuilder field(String name) {
            cw.visitField(Opcodes.ACC_PRIVATE, name, "I", null, null).visitEnd();
            return this;
        }

        ClassBuilder constant(String name, String value) {
            cw.visitField(Opcodes.ACC_STATIC | Opcodes.ACC_FINAL, name, "Ljava/lang/String;", null, value).visitEnd();
            return this;
        }

        ClassBuilder method(String name, String desc, Consumer<MethodVisitor> body) {
            return method(Opcodes.ACC_PUBLIC, name, desc, body);
        }

        ClassBuilder method(int access, String name, String desc, Consumer<MethodVisitor> body) {
            MethodVisitor mv = cw.visitMethod(access, name, desc, null, null);
            if ((access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) == 0) {
                mv.visitCode();
                body.accept(mv);
                mv.visitInsn(Opcodes.RETURN);
                mv.visitMaxs(16, 16);
            }
            mv.visitEnd();
            return this;
        }

        ClassBuilder annotatedMethod(String name, String annotation, Consumer<MethodVisitor> body) {
            MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, name, "()V", null, null);
            mv.visitAnnotation(annotation, true).visitEnd();
            mv.visitCode();
            body.accept(mv);
            mv.visitInsn(Opcodes.RETURN);
            mv.visitMaxs(16, 16);
            mv.visitEnd();
            return this;
        }

        /** Shortcut for a static initializer. */
        ClassBuilder clinit(Consumer<MethodVisitor> body) {
            return method(Opcodes.ACC_STATIC, "<clinit>", "()V", body);
        }

        byte[] bytes() {
            cw.visitEnd();
            return cw.toByteArray();
        }
    }

    static ClassBuilder cls(String name) {
        return new ClassBuilder(name);
    }

    // ---- instruction helpers ----

    static void invokeStatic(MethodVisitor mv, String owner, String name, String desc) {
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner, name, desc, false);
    }

    static void invokeVirtual(MethodVisitor mv, String owner, String name, String desc) {
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, owner, name, desc, false);
    }

    static void newObject(MethodVisitor mv, String owner, String ctorDesc) {
        mv.visitTypeInsn(Opcodes.NEW, owner);
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, owner, "<init>", ctorDesc, false);
    }

    static void ldc(MethodVisitor mv, Object constant) {
        mv.visitLdcInsn(constant);
    }

    /** Emits {@code new String(new byte[]{...})} the way javac compiles it. */
    static void byteArrayString(MethodVisitor mv, String text) {
        byte[] b = text.getBytes(StandardCharsets.UTF_8);
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/String");
        mv.visitInsn(Opcodes.DUP);
        mv.visitIntInsn(Opcodes.SIPUSH, b.length);
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
        for (int i = 0; i < b.length; i++) {
            mv.visitInsn(Opcodes.DUP);
            mv.visitIntInsn(Opcodes.SIPUSH, i);
            mv.visitIntInsn(Opcodes.BIPUSH, b[i]);
            mv.visitInsn(Opcodes.BASTORE);
        }
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([B)V", false);
    }

    /** Emits {@code new String(new char[]{...})}. */
    static void charArrayString(MethodVisitor mv, String text) {
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/String");
        mv.visitInsn(Opcodes.DUP);
        mv.visitIntInsn(Opcodes.SIPUSH, text.length());
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_CHAR);
        for (int i = 0; i < text.length(); i++) {
            mv.visitInsn(Opcodes.DUP);
            mv.visitIntInsn(Opcodes.SIPUSH, i);
            mv.visitIntInsn(Opcodes.SIPUSH, text.charAt(i));
            mv.visitInsn(Opcodes.CASTORE);
        }
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false);
    }

    // ---- archives ----

    /** Builds a ZIP/JAR in memory from alternating entry names and contents (byte[] or String). */
    static byte[] jar(Object... namesAndContents) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (ZipOutputStream zos = new ZipOutputStream(out)) {
                for (int i = 0; i < namesAndContents.length; i += 2) {
                    zos.putNextEntry(new ZipEntry((String) namesAndContents[i]));
                    Object c = namesAndContents[i + 1];
                    zos.write(c instanceof String s ? s.getBytes(StandardCharsets.UTF_8) : (byte[]) c);
                    zos.closeEntry();
                }
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static Path write(Path dir, String name, byte[] bytes) throws IOException {
        Path p = dir.resolve(name);
        Files.write(p, bytes);
        return p;
    }

    /** Starts like a Windows executable. Not a working program. */
    static byte[] fakeWindowsExecutable() {
        byte[] b = new byte[64];
        b[0] = 'M';
        b[1] = 'Z';
        return b;
    }
}
