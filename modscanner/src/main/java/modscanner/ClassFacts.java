package modscanner;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** What the scanner records about one class file. Filled in by {@link ClassAnalyzer}. */
final class ClassFacts {

    /** A method call. {@code methodRef} is true for method handles and references like {@code Runtime::exec}. */
    record Call(String owner, String name, String desc, int line, boolean methodRef) {
    }

    /** Where a string came from. */
    enum Origin {
        /** An ordinary string constant in the code. */
        LITERAL,
        /** Built from constant pieces by string concatenation ("https://" + host). */
        CONCAT,
        /** Rebuilt from {@code new byte[]{...}} filled with constants. */
        BYTE_ARRAY,
        /** Rebuilt from {@code new char[]{...}} filled with constants. */
        CHAR_ARRAY,
        /** A Base64 literal that decodes to readable text. */
        BASE64;

        /** True if the author went out of their way to keep this text from appearing as a plain string. */
        boolean isEncoded() {
            return this == BYTE_ARRAY || this == CHAR_ARRAY || this == BASE64;
        }
    }

    record Str(String value, Origin origin, int line) {
    }

    static final class Method {
        final String name;
        final String desc;
        final int access;
        final List<Call> calls = new ArrayList<>();
        final List<Str> strings = new ArrayList<>();
        /** Classes this method touches in a way that runs their static initializer (new, static access, Foo.class). */
        final Set<String> classRefs = new LinkedHashSet<>();
        final Set<String> annotations = new LinkedHashSet<>();
        /** Set later: does this method run as soon as the mod loads? */
        boolean loadTime;

        Method(String name, String desc, int access) {
            this.name = name;
            this.desc = desc;
            this.access = access;
        }
    }

    /** Internal name, e.g. "com/example/Mod". */
    final String name;
    final String superName;
    final List<String> interfaces;
    final int access;
    /** The archive entry it was read from, e.g. "com/example/Mod.class". */
    final String entryName;
    final List<Method> methods = new ArrayList<>();
    final List<String> fieldNames = new ArrayList<>();
    final Set<String> annotations = new LinkedHashSet<>();

    ClassFacts(String name, String superName, List<String> interfaces, int access, String entryName) {
        this.name = name;
        this.superName = superName;
        this.interfaces = interfaces;
        this.access = access;
        this.entryName = entryName;
    }

    String dottedName() {
        return name.replace('/', '.');
    }

    Method method(String name, String desc) {
        for (Method m : methods) {
            if (m.name.equals(name) && m.desc.equals(desc)) {
                return m;
            }
        }
        return null;
    }
}
