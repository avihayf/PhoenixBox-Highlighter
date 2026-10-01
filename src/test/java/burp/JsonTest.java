package burp;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonTest {

    @Test
    void readsEveryValueType() {
        Map<String, Object> root = Json.asObject(Json.parse(
                "{\"s\":\"a\\\"b\\u00e9\",\"n\":-12,\"d\":1.5,\"t\":true,\"f\":false,\"z\":null,\"a\":[1,[]],\"o\":{}}"));

        assertEquals("a\"bé", root.get("s"));
        assertEquals(-12L, root.get("n"));
        assertEquals(1.5, root.get("d"));
        assertEquals(true, root.get("t"));
        assertEquals(false, root.get("f"));
        assertNull(root.get("z"));
        assertEquals(List.of(1L, List.of()), root.get("a"));
        assertEquals(Map.of(), root.get("o"));
    }

    @Test
    void writesWhatItReads() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("name", "Line\nbreak \"quoted\" \u0001");
        value.put("port", 18080L);
        value.put("list", List.of(true, "x"));
        value.put("none", null);

        assertEquals(value, Json.parse(Json.write(value)));
        assertEquals("{\"port\":8080}", Json.write(Map.of("port", 8080L)));
    }

    @Test
    void readsBurpsPrettyPrintedExport() {
        String export = "{\n    \"proxy\":{\n        \"request_listeners\":[\n            {\n"
                + "                \"listener_port\":8080,\n                \"running\":true\n            }\n        ]\n    }\n}";

        Map<String, Object> proxy = Json.asObject(Json.asObject(Json.parse(export)).get("proxy"));
        assertEquals(1, Json.asArray(proxy.get("request_listeners")).size());
    }

    @Test
    void rejectsMalformedInput() {
        for (String bad : new String[]{"", "{", "{\"a\":}", "[1,]", "{} x", "\"unterminated", "{\"a\" 1}", "tru",
                "\"\u0001\"", null}) {
            assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), String.valueOf(bad));
        }
    }

    @Test
    void rejectsDeepNestingFromUntrustedInput() {
        assertThrows(IllegalArgumentException.class, () -> Json.parse("[".repeat(100) + "]".repeat(100)));
    }
}
