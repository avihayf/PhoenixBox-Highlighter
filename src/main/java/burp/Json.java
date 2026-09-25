package burp;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal JSON reader and writer.
 *
 * <p>Montoya's own JSON nodes are created through a factory that only exists inside a running
 * Burp, so code built on them cannot be unit tested. This covers what the extension needs: Burp's
 * exported listener settings and the PhoenixBox control protocol.
 *
 * <p>Values map to {@link Map} (insertion ordered), {@link List}, {@link String}, {@link Long} or
 * {@link Double}, {@link Boolean} and {@code null}.
 */
final class Json {

    /** Nesting deeper than this is rejected: the control protocol is flat and the input untrusted. */
    private static final int MAX_DEPTH = 32;

    private final String text;
    private int pos;

    private Json(String text) {
        this.text = text;
    }

    static Object parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("no JSON");
        }

        Json parser = new Json(text);
        parser.skipWhitespace();
        Object value = parser.readValue(0);
        parser.skipWhitespace();

        if (parser.pos != text.length()) {
            throw parser.error("trailing characters");
        }

        return value;
    }

    static String write(Object value) {
        StringBuilder out = new StringBuilder();
        writeValue(out, value);
        return out.toString();
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asObject(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    static List<Object> asArray(Object value) {
        return value instanceof List ? (List<Object>) value : null;
    }

    private Object readValue(int depth) {
        if (depth > MAX_DEPTH) {
            throw error("nested too deeply");
        }
        if (pos >= text.length()) {
            throw error("unexpected end");
        }

        char c = text.charAt(pos);
        switch (c) {
            case '{':
                return readObject(depth);
            case '[':
                return readArray(depth);
            case '"':
                return readString();
            case 't':
                expectWord("true");
                return Boolean.TRUE;
            case 'f':
                expectWord("false");
                return Boolean.FALSE;
            case 'n':
                expectWord("null");
                return null;
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return readNumber();
                }
                throw error("unexpected character '" + c + "'");
        }
    }

    private Map<String, Object> readObject(int depth) {
        Map<String, Object> result = new LinkedHashMap<>();
        pos++;
        skipWhitespace();

        if (peek('}')) {
            pos++;
            return result;
        }

        while (true) {
            skipWhitespace();
            if (!peek('"')) {
                throw error("expected a key");
            }
            String key = readString();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            result.put(key, readValue(depth + 1));
            skipWhitespace();

            if (peek(',')) {
                pos++;
                continue;
            }
            expect('}');
            return result;
        }
    }

    private List<Object> readArray(int depth) {
        List<Object> result = new ArrayList<>();
        pos++;
        skipWhitespace();

        if (peek(']')) {
            pos++;
            return result;
        }

        while (true) {
            skipWhitespace();
            result.add(readValue(depth + 1));
            skipWhitespace();

            if (peek(',')) {
                pos++;
                continue;
            }
            expect(']');
            return result;
        }
    }

    private String readString() {
        expect('"');
        StringBuilder out = new StringBuilder();

        while (true) {
            if (pos >= text.length()) {
                throw error("unterminated string");
            }

            char c = text.charAt(pos++);
            if (c == '"') {
                return out.toString();
            }
            if (c < 0x20) {
                throw error("control character in string");
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (pos >= text.length()) {
                throw error("unterminated escape");
            }

            char escaped = text.charAt(pos++);
            switch (escaped) {
                case '"': out.append('"'); break;
                case '\\': out.append('\\'); break;
                case '/': out.append('/'); break;
                case 'b': out.append('\b'); break;
                case 'f': out.append('\f'); break;
                case 'n': out.append('\n'); break;
                case 'r': out.append('\r'); break;
                case 't': out.append('\t'); break;
                case 'u':
                    if (pos + 4 > text.length()) {
                        throw error("short unicode escape");
                    }
                    try {
                        out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                    } catch (NumberFormatException e) {
                        throw error("bad unicode escape");
                    }
                    pos += 4;
                    break;
                default:
                    throw error("bad escape");
            }
        }
    }

    private Object readNumber() {
        int start = pos;
        if (peek('-')) {
            pos++;
        }
        while (pos < text.length() && "0123456789.eE+-".indexOf(text.charAt(pos)) >= 0) {
            pos++;
        }

        String number = text.substring(start, pos);
        try {
            if (number.contains(".") || number.contains("e") || number.contains("E")) {
                return Double.parseDouble(number);
            }
            return Long.parseLong(number);
        } catch (NumberFormatException e) {
            throw error("bad number");
        }
    }

    private void expectWord(String word) {
        if (!text.startsWith(word, pos)) {
            throw error("expected " + word);
        }
        pos += word.length();
    }

    private void expect(char c) {
        if (!peek(c)) {
            throw error("expected '" + c + "'");
        }
        pos++;
    }

    private boolean peek(char c) {
        return pos < text.length() && text.charAt(pos) == c;
    }

    private void skipWhitespace() {
        while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
            pos++;
        }
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException("Invalid JSON at " + pos + ": " + message);
    }

    private static void writeValue(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String) {
            writeString(out, (String) value);
        } else if (value instanceof Boolean || value instanceof Long || value instanceof Integer
                || value instanceof Short || value instanceof Byte) {
            out.append(value);
        } else if (value instanceof Number) {
            double d = ((Number) value).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("JSON cannot represent " + d);
            }
            out.append(d == Math.rint(d) && Math.abs(d) < 1e15 ? Long.toString((long) d) : Double.toString(d));
        } else if (value instanceof Map) {
            out.append('{');
            Iterator<? extends Map.Entry<?, ?>> it = ((Map<?, ?>) value).entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<?, ?> entry = it.next();
                writeString(out, String.valueOf(entry.getKey()));
                out.append(':');
                writeValue(out, entry.getValue());
                if (it.hasNext()) {
                    out.append(',');
                }
            }
            out.append('}');
        } else if (value instanceof List) {
            out.append('[');
            List<?> list = (List<?>) value;
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    out.append(',');
                }
                writeValue(out, list.get(i));
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException("cannot write " + value.getClass().getName() + " as JSON");
        }
    }

    private static void writeString(StringBuilder out, String s) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20 || c == ' ' || c == ' ') {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
    }
}
