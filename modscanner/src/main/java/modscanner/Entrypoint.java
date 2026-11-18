package modscanner;

import java.util.List;

/** A class a mod loader runs when the game starts, as declared by the mod's metadata. */
public final class Entrypoint {
    public final String archive;
    /** fabric, quilt, forge, neoforge, forge-legacy, bukkit, paper, bungeecord, java-main, java-agent, ... */
    public final String loader;
    public final String className;
    /** Methods the loader calls, or ["*"] for all of them. Static initializers and constructors always count. */
    public final List<String> methods;
    /** The file or annotation that declared it. */
    public final String source;
    /** False if the metadata names a class that is not in the archive. Set after parsing. */
    public boolean classFound;

    Entrypoint(String archive, String loader, String className, List<String> methods, String source) {
        this.archive = archive;
        this.loader = loader;
        this.className = className;
        this.methods = methods;
        this.source = source;
    }
}
