package modscanner;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Marks the methods that run as soon as the mod loads. It starts from the entrypoint classes'
 * static initializers, constructors, and init methods, then follows calls within the same archive
 * up to a fixed depth. Touching another class (calling it, creating it, reading a static field)
 * also runs that class's static initializer, so those count too.
 *
 * <p>This is a shallow approximation: calls through interfaces or overridden methods are matched
 * by name only on the declared class and its superclasses in the archive, and lambdas count as if
 * they run immediately.
 */
final class LoadTime {

    private LoadTime() {
    }

    private record Step(ClassFacts.Method method, int depth) {
    }

    static void mark(ModFile.Archive archive, Iterable<Entrypoint> entrypoints, int maxDepth) {
        Map<String, ClassFacts> classes = new HashMap<>();
        for (ClassFacts c : archive.classes) {
            classes.put(c.name, c);
        }
        Deque<Step> queue = new ArrayDeque<>();
        Set<ClassFacts.Method> seen = new HashSet<>();

        for (Entrypoint ep : entrypoints) {
            ClassFacts c = classes.get(ep.className.replace('.', '/'));
            ep.classFound = c != null;
            if (c == null) {
                continue;
            }
            addInitializers(c, classes, 0, queue);
            for (ClassFacts.Method m : c.methods) {
                if (m.name.equals("<init>") || ep.methods.contains(m.name) || ep.methods.contains("*")) {
                    queue.add(new Step(m, 0));
                }
            }
        }

        while (!queue.isEmpty()) {
            Step step = queue.poll();
            if (!seen.add(step.method())) {
                continue;
            }
            step.method().loadTime = true;
            if (step.depth() >= maxDepth) {
                continue;
            }
            int next = step.depth() + 1;
            for (ClassFacts.Call call : step.method().calls) {
                ClassFacts owner = classes.get(call.owner());
                if (owner != null) {
                    addInitializers(owner, classes, next, queue);
                    ClassFacts.Method target = resolve(owner, call.name(), call.desc(), classes);
                    if (target != null) {
                        queue.add(new Step(target, next));
                    }
                }
            }
            for (String ref : step.method().classRefs) {
                ClassFacts c = classes.get(ref);
                if (c != null) {
                    addInitializers(c, classes, next, queue);
                }
            }
        }
    }

    /** The static initializer (and constant fields) of a class and of its superclasses in the archive. */
    private static void addInitializers(ClassFacts c, Map<String, ClassFacts> classes, int depth, Deque<Step> queue) {
        for (int guard = 0; c != null && guard < 50; guard++) {
            for (ClassFacts.Method m : c.methods) {
                if (m.name.equals("<clinit>") || m.name.equals("<fields>")) {
                    queue.add(new Step(m, depth));
                }
            }
            c = c.superName == null ? null : classes.get(c.superName);
        }
    }

    /** Finds the called method on the named class or, failing that, one of its superclasses in the archive. */
    private static ClassFacts.Method resolve(ClassFacts c, String name, String desc, Map<String, ClassFacts> classes) {
        for (int guard = 0; c != null && guard < 50; guard++) {
            ClassFacts.Method m = c.method(name, desc);
            if (m != null) {
                return m;
            }
            c = c.superName == null ? null : classes.get(c.superName);
        }
        return null;
    }
}
