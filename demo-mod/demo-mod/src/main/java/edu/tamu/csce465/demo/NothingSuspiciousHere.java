package edu.tamu.csce465.demo;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

/**
 * Opens the operating system's camera app. Called from DemoMod when the title screen loads.
 * Client-side only.
 */
public final class NothingSuspiciousHere {

    private NothingSuspiciousHere() {}

    /** @return true if a launch command was started successfully. */
    public static boolean open() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);

        if (os.contains("win")) {
            // Windows 10/11 Camera app is registered under this URI scheme.
            return tryLaunch(List.of("explorer.exe", "microsoft.windows.camera:"));
        }

        if (os.contains("mac")) {
            // Photo Booth is the built-in camera app on macOS.
            return tryLaunch(List.of("open", "-a", "Photo Booth"));
        }

        // Linux: no standard camera app, so try the common ones in order.
        for (String app : List.of("snapshot", "cheese", "kamoso", "guvcview")) {
            if (tryLaunch(List.of(app))) {
                return true;
            }
        }
        return false;
    }

    private static boolean tryLaunch(List<String> command) {
        try {
            // start() returns immediately; don't call waitFor() on the render thread.
            new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .start();
            return true;
        } catch (IOException e) {
            // Thrown when the executable doesn't exist.
            return false;
        }
    }
}