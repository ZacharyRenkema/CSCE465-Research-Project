package modscanner;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Turns class file bytes into {@link ClassFacts} using ASM. ASM only parses the bytes; the class is
 * never loaded into the JVM, so none of its code can run.
 */
final class ClassAnalyzer {

    private ClassAnalyzer() {
    }

    /** Version we pretend a too-new class file has, so this ASM release will still read it. */
    private static final int FALLBACK_MAJOR_VERSION = 65;

    static boolean looksLikeClassFile(byte[] b) {
        if (b.length < 10 || readInt(b, 0) != 0xCAFEBABE) {
            return false;
        }
        int major = ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);
        return major >= 45 && major < 200;
    }

    static int readInt(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16) | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    /**
     * @throws RuntimeException if ASM cannot parse the class; the caller reports it as a bad class file
     */
    static ClassFacts analyze(byte[] bytes, String entryName) {
        ClassNode cn = new ClassNode();
        try {
            new ClassReader(bytes).accept(cn, ClassReader.SKIP_FRAMES);
        } catch (IllegalArgumentException e) {
            // ASM refuses class versions newer than it knows. The parts we read have not changed,
            // so read a copy with the version number lowered.
            if (!String.valueOf(e.getMessage()).startsWith("Unsupported class file")) {
                throw e;
            }
            byte[] copy = bytes.clone();
            copy[6] = 0;
            copy[7] = (byte) FALLBACK_MAJOR_VERSION;
            cn = new ClassNode();
            new ClassReader(copy).accept(cn, ClassReader.SKIP_FRAMES);
        }

        ClassFacts facts = new ClassFacts(cn.name, cn.superName,
                cn.interfaces == null ? List.of() : List.copyOf(cn.interfaces), cn.access, entryName);
        addAnnotations(facts.annotations, cn.visibleAnnotations, cn.invisibleAnnotations);

        ClassFacts.Method fieldInit = null;
        for (FieldNode fn : cn.fields) {
            facts.fieldNames.add(fn.name);
            // Constant fields (static final String X = "...") store the value in the field itself.
            if (fn.value instanceof String s) {
                if (fieldInit == null) {
                    fieldInit = new ClassFacts.Method("<fields>", "", 0);
                }
                addString(fieldInit.strings, s, ClassFacts.Origin.LITERAL, 0);
            }
        }
        for (MethodNode mn : cn.methods) {
            facts.methods.add(analyzeMethod(mn));
        }
        if (fieldInit != null) {
            facts.methods.add(fieldInit);
        }
        return facts;
    }

    @SafeVarargs
    private static void addAnnotations(Set<String> out, List<AnnotationNode>... lists) {
        for (List<AnnotationNode> list : lists) {
            if (list != null) {
                for (AnnotationNode a : list) {
                    out.add(a.desc);
                }
            }
        }
    }

    private static ClassFacts.Method analyzeMethod(MethodNode mn) {
        ClassFacts.Method m = new ClassFacts.Method(mn.name, mn.desc, mn.access);
        addAnnotations(m.annotations, mn.visibleAnnotations, mn.invisibleAnnotations);

        int line = 0;
        for (AbstractInsnNode n = mn.instructions.getFirst(); n != null; n = n.getNext()) {
            if (n instanceof LineNumberNode ln) {
                line = ln.line;
            } else if (n instanceof MethodInsnNode mi) {
                m.calls.add(new ClassFacts.Call(mi.owner, mi.name, mi.desc, line, false));
                if (mi.getOpcode() == Opcodes.INVOKESTATIC) {
                    m.classRefs.add(mi.owner);
                }
            } else if (n instanceof InvokeDynamicInsnNode indy) {
                readInvokeDynamic(m, indy, line);
            } else if (n instanceof LdcInsnNode ldc) {
                if (ldc.cst instanceof String s) {
                    addString(m.strings, s, ClassFacts.Origin.LITERAL, line);
                } else if (ldc.cst instanceof Type t && t.getSort() == Type.OBJECT) {
                    m.classRefs.add(t.getInternalName());
                } else if (ldc.cst instanceof Handle h) {
                    m.calls.add(new ClassFacts.Call(h.getOwner(), h.getName(), h.getDesc(), line, true));
                }
            } else if (n instanceof TypeInsnNode ti && ti.getOpcode() == Opcodes.NEW) {
                m.classRefs.add(ti.desc);
            } else if (n instanceof FieldInsnNode fi
                    && (fi.getOpcode() == Opcodes.GETSTATIC || fi.getOpcode() == Opcodes.PUTSTATIC)) {
                m.classRefs.add(fi.owner);
            } else if (n instanceof IntInsnNode ii && ii.getOpcode() == Opcodes.NEWARRAY) {
                readConstantArray(m, ii, line);
            }
        }
        return m;
    }

    /** Lambdas and method references point at their target through a method handle; string concatenation keeps its constant text in a "recipe". */
    private static void readInvokeDynamic(ClassFacts.Method m, InvokeDynamicInsnNode indy, int line) {
        Object[] args = indy.bsmArgs == null ? new Object[0] : indy.bsmArgs;
        if (indy.bsm.getName().equals("makeConcatWithConstants") && args.length > 0 && args[0] instanceof String recipe) {
            // \u0001 stands for a value only known at run time; \u0002 for a constant passed separately.
            StringBuilder sb = new StringBuilder();
            int nextConstant = 1;
            for (char c : recipe.toCharArray()) {
                if (c == '\u0002' && nextConstant < args.length) {
                    sb.append(args[nextConstant++]);
                } else {
                    sb.append(c == '\u0001' ? Strings.UNKNOWN : c);
                }
            }
            addString(m.strings, sb.toString(), ClassFacts.Origin.CONCAT, line);
            return;
        }
        for (Object a : args) {
            if (a instanceof Handle h) {
                m.calls.add(new ClassFacts.Call(h.getOwner(), h.getName(), h.getDesc(), line, true));
            }
        }
    }

    /**
     * Rebuilds strings hidden as {@code new String(new byte[]{104, 116, 116, 112, ...})}. The compiler
     * turns each element into: DUP, push index, push value, BASTORE (CASTORE for char arrays).
     */
    private static void readConstantArray(ClassFacts.Method m, IntInsnNode newArray, int line) {
        boolean isByte = newArray.operand == Opcodes.T_BYTE;
        if (!isByte && newArray.operand != Opcodes.T_CHAR) {
            return;
        }
        int storeOpcode = isByte ? Opcodes.BASTORE : Opcodes.CASTORE;
        List<Integer> values = new ArrayList<>();
        AbstractInsnNode n = next(newArray);
        while (n != null && n.getOpcode() == Opcodes.DUP) {
            AbstractInsnNode index = next(n);
            AbstractInsnNode value = next(index);
            AbstractInsnNode store = next(value);
            Integer i = intConstant(index);
            Integer v = intConstant(value);
            if (i == null || v == null || store == null || store.getOpcode() != storeOpcode || i != values.size()) {
                break;
            }
            values.add(v);
            n = next(store);
        }
        if (values.size() < 4) {
            return;
        }
        String text;
        if (isByte) {
            byte[] raw = new byte[values.size()];
            for (int i = 0; i < raw.length; i++) {
                raw[i] = (byte) (int) values.get(i);
            }
            text = Strings.readableText(raw);
        } else {
            StringBuilder sb = new StringBuilder();
            values.forEach(v -> sb.append((char) (int) v));
            text = Strings.isReadable(sb.toString()) ? sb.toString() : null;
        }
        if (text != null) {
            addString(m.strings, text, isByte ? ClassFacts.Origin.BYTE_ARRAY : ClassFacts.Origin.CHAR_ARRAY, line);
        }
    }

    /** Adds a string, plus its decoded text if it is Base64 for readable text (checked twice, for double encoding). */
    private static void addString(List<ClassFacts.Str> out, String s, ClassFacts.Origin origin, int line) {
        out.add(new ClassFacts.Str(s, origin, line));
        String decoded = Strings.base64(s);
        for (int depth = 0; decoded != null && depth < 2; depth++) {
            out.add(new ClassFacts.Str(decoded, ClassFacts.Origin.BASE64, line));
            decoded = Strings.base64(decoded);
        }
    }

    /** Next real instruction, skipping labels, line numbers, and frames. */
    private static AbstractInsnNode next(AbstractInsnNode n) {
        if (n == null) {
            return null;
        }
        n = n.getNext();
        while (n != null && n.getOpcode() < 0) {
            n = n.getNext();
        }
        return n;
    }

    static Integer intConstant(AbstractInsnNode n) {
        if (n == null) {
            return null;
        }
        int op = n.getOpcode();
        if (op >= Opcodes.ICONST_M1 && op <= Opcodes.ICONST_5) {
            return op - Opcodes.ICONST_0;
        }
        if ((op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) && n instanceof IntInsnNode ii) {
            return ii.operand;
        }
        if (n instanceof LdcInsnNode ldc && ldc.cst instanceof Integer v) {
            return v;
        }
        return null;
    }
}
