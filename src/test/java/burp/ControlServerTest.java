package burp;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ControlServerTest {

    private static final String TOKEN = "secret-token";

    private final SyncService sync = new SyncService(
            new ListenerManager(new ListenerManagerTest.FakeOptions(ListenerConfigTest.export(ListenerConfigTest.USER_8080)),
                    new ListenerManagerTest.MapStore()),
            new ContainerRegistry(), new KnownNames(null),
            new AddressProbe() {
                @Override
                public Result probe(ListenerAddress address) {
                    return Result.FREE;
                }

                @Override
                public boolean answers(ListenerAddress address) {
                    return true;
                }
            },
            ListenerAddress.parse("127.0.0.1:8079"), System::currentTimeMillis);

    private final ControlServer.Handler handler = new ControlServer.Handler(() -> TOKEN, sync);

    private static ControlServer.Request request(String method, String path, String body, String... headers) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < headers.length; i += 2) {
            map.put(headers[i], headers[i + 1]);
        }
        return new ControlServer.Request(method, path, map, body);
    }

    private static final String SYNC_BODY = "{\"protocol\":1,\"preset\":{\"host\":\"127.0.0.1\",\"port\":8080},"
            + "\"containers\":[{\"id\":\"a\",\"name\":\"A\",\"color\":\"red\"}]}";

    @Test
    void servesStatusToAPairedCaller() {
        ControlServer.Response response = handler.handle(request("GET", "/v1/status", "",
                "authorization", "Bearer " + TOKEN, "origin", "moz-extension://1234"));

        assertEquals(200, response.status());
        assertTrue(response.body().contains("\"protocol\":1"), response.body());
    }

    @Test
    void syncsForAPairedCaller() {
        ControlServer.Response response = handler.handle(request("POST", "/v1/sync", SYNC_BODY,
                "authorization", "Bearer " + TOKEN, "content-type", "application/json"));

        assertEquals(200, response.status());
        assertTrue(response.body().contains("127.0.0.1:18080"), response.body());
    }

    @Test
    void refusesAWrongOrMissingToken() {
        assertEquals(401, handler.handle(request("GET", "/v1/status", "")).status());
        assertEquals(401, handler.handle(request("GET", "/v1/status", "", "authorization", "Bearer nope")).status());
        assertEquals(401, handler.handle(request("GET", "/v1/status", "", "authorization", TOKEN)).status());
    }

    @Test
    void refusesWebPagesEvenWithTheToken() {
        ControlServer.Response response = handler.handle(request("POST", "/v1/sync", SYNC_BODY,
                "authorization", "Bearer " + TOKEN, "content-type", "application/json",
                "origin", "https://evil.example"));

        assertEquals(403, response.status());
    }

    @Test
    void refusesEveryPreflight() {
        assertEquals(405, handler.handle(request("OPTIONS", "/v1/sync", "",
                "origin", "https://evil.example", "authorization", "Bearer " + TOKEN)).status());
    }

    @Test
    void requiresJsonForSync() {
        assertEquals(415, handler.handle(request("POST", "/v1/sync", SYNC_BODY,
                "authorization", "Bearer " + TOKEN, "content-type", "text/plain")).status());
        assertEquals(400, handler.handle(request("POST", "/v1/sync", "{not json",
                "authorization", "Bearer " + TOKEN, "content-type", "application/json")).status());
        assertEquals(400, handler.handle(request("POST", "/v1/sync", "{\"protocol\":9}",
                "authorization", "Bearer " + TOKEN, "content-type", "application/json")).status());
    }

    @Test
    void answersUnknownPathsWithNotFound() {
        assertEquals(404, handler.handle(request("GET", "/", "", "authorization", "Bearer " + TOKEN)).status());
    }

    @Test
    void readsARequestOffTheWire() throws IOException {
        String raw = "POST /v1/sync?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                + "Content-Length: 2\r\n\r\n{}";

        ControlServer.Request request = ControlServer.read(stream(raw));

        assertEquals("POST", request.method());
        assertEquals("/v1/sync", request.path());
        assertEquals("application/json", request.headers().get("content-type"));
        assertEquals("{}", request.body());
    }

    @Test
    void refusesOversizedOrTruncatedRequests() throws IOException {
        assertNull(ControlServer.read(stream("GET / HTTP/1.1\r\n" + "X: y\r\n".repeat(2000) + "\r\n")));
        assertNull(ControlServer.read(stream("POST / HTTP/1.1\r\nContent-Length: 999999\r\n\r\n")));
        assertNull(ControlServer.read(stream("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n{}")));
        assertNull(ControlServer.read(stream("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")));
        assertNull(ControlServer.read(stream("GARBAGE\r\n\r\n")));
        assertNull(ControlServer.read(stream("GET / HTTP/1.1\r\n")));
    }

    @Test
    void pairingStringCarriesHostPortAndToken() {
        assertEquals("phx1:127.0.0.1:8079:abc", Pairing.pairingString("127.0.0.1", 8079, "abc"));
        assertEquals("phx1:[::1]:8079:abc", Pairing.pairingString("::1", 8079, "abc"));
        assertTrue(Pairing.newToken().matches("[A-Za-z0-9_-]{43}"));
    }

    @Test
    void bindsTheControlServerWhereTheFirstProxyListenerIs() {
        assertEquals("127.0.0.1", Pairing.bindHost(ListenerConfig.parse(
                ListenerConfigTest.export(ListenerConfigTest.USER_8080))));
        assertEquals("192.168.10.2", Pairing.bindHost(ListenerConfig.parse(
                ListenerConfigTest.export(ListenerConfigTest.specific("192.168.10.2", 8080)))));
        assertEquals("0.0.0.0", Pairing.bindHost(ListenerConfig.parse(
                ListenerConfigTest.export(ListenerConfigTest.allInterfaces(8080)))));
        assertEquals("127.0.0.1", Pairing.bindHost(ListenerConfig.parse(ListenerConfigTest.export())));
    }

    @Test
    void rebindsItsPortWhileOldConnectionsSitInTimeWait() throws Exception {
        // PhoenixBox's syncs leave the control port's connections in TIME_WAIT. A reload must get
        // the same port back, or the pairing string changes under the user.
        int port;
        try (java.net.ServerSocket old = new java.net.ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress());
             java.net.Socket client = new java.net.Socket(java.net.InetAddress.getLoopbackAddress(), old.getLocalPort())) {
            port = old.getLocalPort();
            try (java.net.Socket accepted = old.accept()) {
                accepted.getOutputStream().write(1);
            }
            client.getInputStream().read();
            client.getInputStream().read();
        }

        ControlServer server = new ControlServer(handler, message -> { });
        try {
            assertEquals(port, server.start("127.0.0.1", port, port));
        } finally {
            server.stop();
        }
    }

    @Test
    void skipsAPortSomethingElseAnswersOn() throws Exception {
        try (java.net.ServerSocket other = new java.net.ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())) {
            ControlServer server = new ControlServer(handler, message -> { });
            int port = other.getLocalPort();
            org.junit.jupiter.api.Assertions.assertThrows(IOException.class,
                    () -> server.start("127.0.0.1", port, port));
            server.stop();
        }
    }

    private static ByteArrayInputStream stream(String raw) {
        return new ByteArrayInputStream(raw.getBytes(StandardCharsets.ISO_8859_1));
    }
}
