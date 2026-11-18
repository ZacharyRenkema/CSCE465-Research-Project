# CSCE465 Demo (benign)

A Fabric client mod that draws "Hello CSCE465!" on the Minecraft title screen.
It is the clean example for our mod scanner: no network, files, or processes, so
the scanner should rate it LOW.

## Build and test

    ./gradlew runClient     # launch Minecraft (offline, no account) and see the text
    ./gradlew build         # produce build/libs/csce465-demo-1.0.0.jar

## Scan it

    java -jar ../modscanner/target/modscanner-0.1.0.jar build/libs/csce465-demo-1.0.0.jar

Versions live in gradle.properties. If one fails to resolve, replace the Fabric
version block with the current set for Minecraft 1.21.1 from https://fabricmc.net/develop.
