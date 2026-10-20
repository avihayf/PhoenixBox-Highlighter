package burp;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ListenerConfigTest {

    /** Exactly what Burp 2026.8 exported in the feasibility spike, plus a custom field to preserve. */
    static final String USER_8080 = "{\"certificate_mode\":\"per_host\",\"custom_tls_protocols\":[],"
            + "\"enable_http2\":true,\"listen_mode\":\"loopback_only\",\"listener_port\":8080,\"running\":true,"
            + "\"support_invisible_proxying\":true,\"use_custom_tls_protocols\":false}";

    static String export(String... listeners) {
        return "{\"proxy\":{\"request_listeners\":[" + String.join(",", listeners) + "]}}";
    }

    static String specific(String ip, int port) {
        return "{\"listen_mode\":\"specific_address\",\"listen_specific_address\":\"" + ip + "\",\"listener_port\":"
                + port + ",\"running\":true}";
    }

    static String allInterfaces(int port) {
        return "{\"listen_mode\":\"all_interfaces\",\"listener_port\":" + port + ",\"running\":true}";
    }

    static ListenerAddress at(String address) {
        return ListenerAddress.parse(address);
    }

    @Test
    void parsesAddressesAndNormalisesLocalhost() {
        assertEquals(new ListenerAddress("127.0.0.1", 18080), at("localhost:18080"));
        assertEquals(new ListenerAddress("::1", 8080), at("[::1]:8080"));
        assertEquals("[::1]:8080", at("[::1]:8080").toString());
        assertEquals("192.168.10.2:8080", at(" 192.168.10.2:8080 ").toString());

        for (String bad : new String[]{"", "8080", "host:", ":80", "host:0", "host:70000", "host:x", "::1:80"}) {
            assertThrows(IllegalArgumentException.class, () -> at(bad), bad);
            assertNull(ListenerAddress.tryParse(bad));
        }
    }

    @Test
    void loopbackOnlyCoversJust127001() {
        ListenerConfig.Entry entry = ListenerConfig.parse(export(USER_8080)).get(0);

        assertTrue(entry.overlaps(at("127.0.0.1:8080")));
        assertFalse(entry.overlaps(at("127.0.0.2:8080")));
        assertFalse(entry.overlaps(at("192.168.10.2:8080")));
        assertFalse(entry.overlaps(at("127.0.0.1:8081")));
    }

    @Test
    void allInterfacesCoversEveryIpOnItsPort() {
        ListenerConfig.Entry entry = ListenerConfig.parse(export(allInterfaces(8080))).get(0);

        assertTrue(entry.overlaps(at("127.0.0.1:8080")));
        assertTrue(entry.overlaps(at("192.168.10.2:8080")));
        assertFalse(entry.overlaps(at("192.168.10.2:8081")));
    }

    @Test
    void specificAddressCoversOnlyItsIp() {
        ListenerConfig.Entry entry = ListenerConfig.parse(export(specific("192.168.10.2", 8080))).get(0);

        assertTrue(entry.overlaps(at("192.168.10.2:8080")));
        assertFalse(entry.overlaps(at("192.168.10.3:8080")));
        assertFalse(entry.overlaps(at("127.0.0.1:8080")));
    }

    @Test
    void addsFreshListenersWithDefaultsNotTheUsersSettings() {
        String json = ListenerConfig.rewrite(export(USER_8080), Set.of(),
                Set.of(at("127.0.0.1:18080"), at("192.168.10.2:18081")));

        List<Object> listeners = listeners(json);
        assertEquals(3, listeners.size());

        Map<String, Object> loopback = Json.asObject(listeners.get(1));
        Map<String, Object> lan = Json.asObject(listeners.get(2));
        Set<Map<String, Object>> added = Set.of(loopback, lan);
        for (Map<String, Object> listener : added) {
            // The user's invisible-proxying flag must not leak onto container listeners.
            assertFalse(listener.containsKey("support_invisible_proxying"));
            assertEquals("per_host", listener.get("certificate_mode"));
            assertEquals(true, listener.get("running"));
        }
        List<ListenerConfig.Entry> entries = ListenerConfig.parse(json);
        assertTrue(entries.stream().anyMatch(e -> e.isExactly(at("127.0.0.1:18080"))));
        assertTrue(entries.stream().anyMatch(e -> e.isExactly(at("192.168.10.2:18081"))));
    }

    @Test
    void removesOnlyExactlyTheNamedListenersAndKeepsOthersVerbatim() {
        String json = ListenerConfig.rewrite(
                export(USER_8080, specific("127.0.0.1", 18080), allInterfaces(18081)),
                Set.of(at("127.0.0.1:18080"), at("127.0.0.1:18081")), Set.of());

        List<Object> listeners = listeners(json);
        // 18080 is removed. The all-interfaces 18081 listener merely overlaps 127.0.0.1:18081, so it
        // is the user's and stays.
        assertEquals(2, listeners.size());
        assertEquals(Json.parse(USER_8080), listeners.get(0));
        assertEquals(Json.parse(allInterfaces(18081)), listeners.get(1));
    }

    @Test
    void neverRemovesTheUsersLoopbackListenerThroughASpecificAddressOfTheSamePort() {
        String json = ListenerConfig.rewrite(export(USER_8080), Set.of(at("127.0.0.2:8080")), Set.of());
        assertEquals(1, listeners(json).size());
    }

    @Test
    void treatsAMissingListenerListAsEmpty() {
        assertTrue(ListenerConfig.parse("{\"proxy\":{}}").isEmpty());
        assertEquals(1, listeners(ListenerConfig.rewrite("{}", Set.of(), Set.of(at("127.0.0.1:18080")))).size());
    }

    private static List<Object> listeners(String json) {
        return Json.asArray(Json.asObject(Json.asObject(Json.parse(json)).get("proxy")).get("request_listeners"));
    }
}
