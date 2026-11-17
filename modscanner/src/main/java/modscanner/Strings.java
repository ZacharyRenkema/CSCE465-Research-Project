package modscanner;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Pattern;

/** Small string helpers: Base64 decoding, readability checks, and normalizing paths for matching. */
final class Strings {

    private Strings() {
    }

    /** Stands in for a part of a concatenated string that is only known at run time. */
    static final String UNKNOWN = "…";

    /** Shorter Base64-looking strings are mostly ordinary words and identifiers, so they are skipped. */
    private static final int MIN_BASE64_LENGTH = 12;
    private static final Pattern BASE64 = Pattern.compile("[A-Za-z0-9+/]+={0,2}");
    private static final Pattern BASE64_URL_SAFE = Pattern.compile("[A-Za-z0-9_-]+={0,2}");

    /** The decoded text if {@code s} is Base64 for readable text, otherwise null. */
    static String base64(String s) {
        String t = s.trim();
        if (t.length() < MIN_BASE64_LENGTH) {
            return null;
        }
        Base64.Decoder decoder;
        if (BASE64.matcher(t).matches()) {
            decoder = Base64.getDecoder();
        } else if (BASE64_URL_SAFE.matcher(t).matches()) {
            decoder = Base64.getUrlDecoder();
        } else {
            return null;
        }
        String body = t.replace("=", "");
        if (body.length() % 4 == 1) {
            return null;
        }
        StringBuilder padded = new StringBuilder(body);
        while (padded.length() % 4 != 0) {
            padded.append('=');
        }
        try {
            return readableText(decoder.decode(padded.toString()));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Reads bytes as UTF-8 (or Latin-1 if not valid UTF-8) and returns them only if they look like text. */
    static String readableText(byte[] raw) {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) {
            text = new String(raw, StandardCharsets.ISO_8859_1);
        }
        return isReadable(text) ? text : null;
    }

    /** At least 4 characters, and at least 90% of them printable ASCII or whitespace. */
    static boolean isReadable(String s) {
        if (s.length() < 4) {
            return false;
        }
        int printable = 0;
        for (char c : s.toCharArray()) {
            if ((c >= 0x20 && c <= 0x7e) || c == '\n' || c == '\r' || c == '\t') {
                printable++;
            }
        }
        return printable * 10 >= s.length() * 9;
    }

    /** Lower case with backslashes turned into slashes, so Windows and Unix paths match the same patterns. */
    static String normalize(String s) {
        return s.toLowerCase(Locale.ROOT).replace('\\', '/');
    }
}
