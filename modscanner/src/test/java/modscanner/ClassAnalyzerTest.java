package modscanner;

import org.junit.Test;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static modscanner.Fixtures.cls;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class ClassAnalyzerTest {

    private static ClassFacts analyze(byte[] b) {
        return ClassAnalyzer.analyze(b, "Test.class");
    }

    private static boolean hasString(ClassFacts c, String value, ClassFacts.Origin origin) {
        for (ClassFacts.Method m : c.methods) {
            for (ClassFacts.Str s : m.strings) {
                if (s.value().equals(value) && s.origin() == origin) {
                    return true;
                }
            }
        }
        return false;
    }

    @Test
    public void recordsCallsStringsAndClassRefs() {
        ClassFacts c = analyze(cls("com/example/A").clinit(mv -> {
            Fixtures.ldc(mv, "hello");
            Fixtures.invokeStatic(mv, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;");
            Fixtures.newObject(mv, "com/example/Helper", "()V");
            Fixtures.ldc(mv, Type.getObjectType("com/example/Other"));
        }).bytes());
        ClassFacts.Method clinit = c.method("<clinit>", "()V");
        assertEquals("java/lang/Runtime", clinit.calls.get(0).owner());
        assertEquals("getRuntime", clinit.calls.get(0).name());
        assertTrue(clinit.classRefs.contains("com/example/Helper"));
        assertTrue(clinit.classRefs.contains("com/example/Other"));
        assertTrue(hasString(c, "hello", ClassFacts.Origin.LITERAL));
    }

    @Test
    public void recordsMethodReferences() {
        Handle exec = new Handle(Opcodes.H_INVOKEVIRTUAL, "java/lang/Runtime", "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;", false);
        Handle metafactory = new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/LambdaMetafactory", "metafactory",
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;"
                        + "Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)"
                        + "Ljava/lang/invoke/CallSite;", false);
        ClassFacts c = analyze(cls("com/example/A").method("run", "()V", mv -> mv.visitInvokeDynamicInsn(
                "apply", "()Ljava/util/function/Function;", metafactory,
                Type.getType("(Ljava/lang/Object;)Ljava/lang/Object;"), exec,
                Type.getType("(Ljava/lang/String;)Ljava/lang/Process;"))).bytes());
        ClassFacts.Call call = c.method("run", "()V").calls.get(0);
        assertEquals("exec", call.name());
        assertTrue(call.methodRef());
    }

    @Test
    public void rebuildsByteArrayString() {
        ClassFacts c = analyze(cls("com/example/A")
                .clinit(mv -> Fixtures.byteArrayString(mv, "http://203.0.113.7:8080/x")).bytes());
        assertTrue(hasString(c, "http://203.0.113.7:8080/x", ClassFacts.Origin.BYTE_ARRAY));
    }

    @Test
    public void rebuildsCharArrayString() {
        ClassFacts c = analyze(cls("com/example/A")
                .clinit(mv -> Fixtures.charArrayString(mv, "java.lang.Runtime")).bytes());
        assertTrue(hasString(c, "java.lang.Runtime", ClassFacts.Origin.CHAR_ARRAY));
    }

    @Test
    public void ignoresBinaryByteArrays() {
        ClassFacts c = analyze(cls("com/example/A").clinit(mv -> {
            mv.visitIntInsn(Opcodes.BIPUSH, 6);
            mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
            for (int i = 0; i < 6; i++) {
                mv.visitInsn(Opcodes.DUP);
                mv.visitIntInsn(Opcodes.BIPUSH, i);
                mv.visitIntInsn(Opcodes.BIPUSH, -100 + i); // not text
                mv.visitInsn(Opcodes.BASTORE);
            }
        }).bytes());
        assertTrue(c.method("<clinit>", "()V").strings.isEmpty());
    }

    @Test
    public void decodesBase64Literals() {
        String url = "https://example.invalid/payload";
        String encoded = Base64.getEncoder().encodeToString(url.getBytes(StandardCharsets.UTF_8));
        String twice = Base64.getEncoder().encodeToString(encoded.getBytes(StandardCharsets.UTF_8));
        ClassFacts c = analyze(cls("com/example/A")
                .method("a", "()V", mv -> Fixtures.ldc(mv, encoded))
                .method("b", "()V", mv -> Fixtures.ldc(mv, twice))
                .bytes());
        assertTrue(hasString(c, url, ClassFacts.Origin.BASE64));
        assertEquals(2, c.method("b", "()V").strings.stream()
                .filter(s -> s.origin() == ClassFacts.Origin.BASE64).count());
    }

    @Test
    public void decodesBase64InConstantFields() {
        String encoded = Base64.getEncoder().encodeToString("discord.com/api/webhooks/1".getBytes(StandardCharsets.UTF_8));
        ClassFacts c = analyze(cls("com/example/A").constant("URL", encoded).bytes());
        assertTrue(hasString(c, "discord.com/api/webhooks/1", ClassFacts.Origin.BASE64));
    }

    @Test
    public void leavesOrdinaryStringsAlone() {
        assertNull(Strings.base64("MinecraftClient"));
        assertNull(Strings.base64("hello world, this is text"));
        assertNull(Strings.base64("abcdefghijklmnop")); // valid Base64 alphabet, decodes to binary
        assertFalse(Strings.isReadable("ab"));
    }

    @Test
    public void readsConcatenationRecipes() {
        Handle concat = new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/StringConcatFactory",
                "makeConcatWithConstants", "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                + "Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;", false);
        ClassFacts c = analyze(cls("com/example/A").method("run", "(Ljava/lang/String;)V", mv -> {
            mv.visitVarInsn(Opcodes.ALOAD, 1);
            mv.visitInvokeDynamicInsn("makeConcatWithConstants", "(Ljava/lang/String;)Ljava/lang/String;", concat,
                    "\u0001/AppData/Local/Google/Chrome/User Data");
        }).bytes());
        assertTrue(hasString(c, Strings.UNKNOWN + "/AppData/Local/Google/Chrome/User Data", ClassFacts.Origin.CONCAT));
    }

    @Test
    public void recordsAnnotationsAndFields() {
        ClassFacts c = analyze(cls("com/example/A")
                .annotation("Lnet/minecraftforge/fml/common/Mod;")
                .field("count")
                .annotatedMethod("init", "Lnet/minecraftforge/fml/common/Mod$EventHandler;", mv -> { })
                .bytes());
        assertTrue(c.annotations.contains("Lnet/minecraftforge/fml/common/Mod;"));
        assertEquals("count", c.fieldNames.get(0));
        assertTrue(c.method("init", "()V").annotations.contains("Lnet/minecraftforge/fml/common/Mod$EventHandler;"));
    }
}
