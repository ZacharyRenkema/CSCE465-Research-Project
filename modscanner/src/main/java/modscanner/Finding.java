package modscanner;

/** One piece of evidence for one signal. Written as-is into the JSON report. */
public final class Finding {
    public final Signal signal;
    /** The archive it came from: "mod.jar", or "mod.jar!/META-INF/jars/lib.jar" for a nested JAR. */
    public final String archive;
    /** Dotted class name, or the file path inside the archive for evidence that is a file. */
    public final String location;
    /** Method name, or null for class-level and file-level evidence. */
    public final String method;
    /** The API call or string that triggered the rule. */
    public final String evidence;
    /** call, method_ref, reflection, string, class, or file. */
    public final String via;
    public final Integer line;
    /** True if the evidence is in code that runs as soon as the mod loads. */
    public final boolean loadTime;

    Finding(Signal signal, String archive, String location, String method, String evidence, String via,
            int line, boolean loadTime) {
        this.signal = signal;
        this.archive = archive;
        this.location = location;
        this.method = method;
        this.evidence = evidence;
        this.via = via;
        this.line = line > 0 ? line : null;
        this.loadTime = loadTime;
    }

    /** "com.example.Mod.onInitialize" or "natives/helper.dll". */
    String where() {
        return method == null ? location : location + "." + method;
    }

    @Override
    public String toString() {
        return signal.id + " @ " + where() + ": " + evidence;
    }
}
