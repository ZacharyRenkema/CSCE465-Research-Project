package modscanner;

import com.google.gson.annotations.SerializedName;

/** The ten static signals from the paper. Weights live in the config file, not here. */
public enum Signal {
    @SerializedName("network_access")
    NETWORK_ACCESS("network_access",
            "This mod can connect to the internet. Many safe mods do this to check for updates, "
                    + "but it is also how stolen data gets sent away or more malware gets downloaded."),

    @SerializedName("native_code")
    NATIVE_CODE("native_code",
            "This mod includes or loads code that runs directly on your computer instead of inside Java. "
                    + "This scanner cannot read that code, so it cannot tell you what it does."),

    @SerializedName("obfuscated_code")
    OBFUSCATED_CODE("obfuscated_code",
            "Parts of this mod look scrambled or hidden on purpose, which makes it hard to check what it does."),

    @SerializedName("encoded_strings")
    ENCODED_STRINGS("encoded_strings",
            "This mod hides web addresses or other text inside scrambled data so they are hard to spot."),

    @SerializedName("runtime_class_loading")
    RUNTIME_CLASS_LOADING("runtime_class_loading",
            "This mod can load and run new code that is not inside the mod file, so what it does can change "
                    + "after you install it."),

    @SerializedName("process_execution")
    PROCESS_EXECUTION("process_execution",
            "This mod can start other programs on your computer, outside of Minecraft."),

    @SerializedName("webhooks_or_paste_sites")
    WEBHOOKS_OR_PASTE_SITES("webhooks_or_paste_sites",
            "This mod contains links to services attackers often use to collect stolen data or host malware, "
                    + "such as Discord webhooks or paste sites."),

    @SerializedName("sensitive_file_access")
    SENSITIVE_FILE_ACCESS("sensitive_file_access",
            "This mod looks for places where logins are kept: saved browser passwords, Discord, Minecraft "
                    + "launcher accounts, or your Minecraft login token. A normal mod has no reason to do this."),

    @SerializedName("persistence_paths")
    PERSISTENCE_PATHS("persistence_paths",
            "This mod mentions places that make a program start by itself every time your computer turns on."),

    @SerializedName("modifies_other_jars")
    MODIFIES_OTHER_JARS("modifies_other_jars",
            "This mod can rewrite other mod files, which is how some malware spreads to your other mods.");

    /** Identifier used in the config file and the JSON report. */
    public final String id;
    /** One sentence for a player with no security background. */
    public final String plainLanguage;

    Signal(String id, String plainLanguage) {
        this.id = id;
        this.plainLanguage = plainLanguage;
    }

    static Signal fromId(String id) {
        for (Signal s : values()) {
            if (s.id.equals(id)) {
                return s;
            }
        }
        throw new IllegalArgumentException("unknown signal '" + id + "'");
    }
}
