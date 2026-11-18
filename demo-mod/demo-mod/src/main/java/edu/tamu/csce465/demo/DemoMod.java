package edu.tamu.csce465.demo;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.screen.v1.ScreenEvents;
import net.minecraft.client.gui.screen.TitleScreen;
import net.minecraft.text.Text;

public class DemoMod implements ClientModInitializer {

    private static boolean cameraOpened = false;

    @Override
    public void onInitializeClient() {
        ScreenEvents.AFTER_INIT.register((client, screen, width, height) -> {
            if (screen instanceof TitleScreen) {
                if (!cameraOpened) {
                    cameraOpened = true;
                    NothingSuspiciousHere.open();
                }

                ScreenEvents.afterRender(screen).register((s, context, mouseX, mouseY, delta) ->
                    context.drawCenteredTextWithShadow(
                        client.textRenderer, Text.literal("Hello CSCE465!"),
                        width / 2, 20, 0xFFFFFF));
            }
        });
    }
}