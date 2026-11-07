package burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.websocket.*;
import burp.api.montoya.websocket.Direction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class WebSocketHighlighterTest {
    @Test
    void matchesAnUpgradeToItsOriginalContainer() {
        try (var highlighter = new WebSocketHighlighter()) {
            highlighter.rememberUpgrade(upgrade(1, "key", "/chat", false), HighlightColor.RED, "Work");
            Wire wire = open(highlighter, upgrade(91, "key", "/chat", false));
            assertLabel(wire, HighlightColor.RED, "Work");
        }
    }

    @Test
    void separatesDestinations() {
        try (var highlighter = new WebSocketHighlighter()) {
            highlighter.rememberUpgrade(upgrade(1, "key", "/chat", false), HighlightColor.RED, "Work");
            highlighter.rememberUpgrade(upgrade(2, "key", "/other", true), HighlightColor.BLUE, "Admin");
            assertLabel(open(highlighter, upgrade(99, "key", "/other", true)), HighlightColor.BLUE, "Admin");
            assertLabel(open(highlighter, upgrade(98, "key", "/chat", false)), HighlightColor.RED, "Work");
        }
    }

    @Test
    void doesNotGuessForUnknownUpgrades() {
        try (var highlighter = new WebSocketHighlighter()) {
            highlighter.rememberUpgrade(upgrade(1, "key", "/chat", false), HighlightColor.RED, "Work");
            assertNull(open(highlighter, upgrade(2, "different", "/chat", false)).handler.get());
            assertNull(open(highlighter, upgrade(3, "key", "/chat", true)).handler.get());
            assertNull(open(highlighter, upgrade(4, "key", "/different", false)).handler.get());
        }
    }

    @Test
    void duplicateKeysIncludingUnattributedTrafficAreAmbiguous() {
        try (var highlighter = new WebSocketHighlighter()) {
            highlighter.rememberUpgrade(upgrade(1, "same", "/chat", false), HighlightColor.RED, "Work");
            highlighter.rememberUpgrade(upgrade(2, "same", "/chat", false), null, null);
            assertNull(open(highlighter, upgrade(9, "same", "/chat", false)).handler.get());
            assertNull(open(highlighter, upgrade(10, "same", "/chat", false)).handler.get());
        }
    }

    @Test
    void repeatedObservationsDoNotCreateAnAmbiguousHandshake() {
        try (var highlighter = new WebSocketHighlighter()) {
            var request = upgrade(1, "key", "/chat", false);
            highlighter.rememberUpgrade(request, HighlightColor.RED, "Work");
            highlighter.rememberUpgrade(request, HighlightColor.BLUE, "Changed");
            highlighter.observeUpgradeToBeSent(upgrade(1, "key", "/chat", false));
            assertLabel(open(highlighter, request), HighlightColor.RED, "Work");
            assertNull(open(highlighter, request).handler.get(), "a binding is consumed once");
        }
    }

    @Test
    void finalHandshakeEditsKeepTheOriginalAttribution() {
        try (var highlighter = new WebSocketHighlighter()) {
            highlighter.rememberUpgrade(upgrade(1, "before", "/chat", false), HighlightColor.RED, "Work");
            highlighter.observeUpgradeToBeSent(upgrade(1, "after", "/edited", true));
            assertLabel(open(highlighter, upgrade(99, "after", "/edited", true)), HighlightColor.RED, "Work");
            assertNull(open(highlighter, upgrade(98, "before", "/chat", false)).handler.get());
        }
    }

    @Test
    void ignoresNonUpgradesAndMissingKeys() {
        try (var highlighter = new WebSocketHighlighter()) {
            var plain = upgrade(1, "key", "/chat", false);
            var nonUpgradeHeaders = List.of(header("Upgrade", "h2c"), header("Sec-WebSocket-Key", "key"));
            when(plain.headers()).thenReturn(nonUpgradeHeaders);
            highlighter.rememberUpgrade(plain, HighlightColor.RED, "Work");
            assertNull(open(highlighter, upgrade(3, "key", "/chat", false)).handler.get());
            var noKey = upgrade(2, "", "/chat", false);
            highlighter.rememberUpgrade(noKey, HighlightColor.RED, "Work");
            assertNull(open(highlighter, noKey).handler.get());
        }
    }

    @Test
    void boundsAndExpiresPendingHandshakes() {
        AtomicLong clock = new AtomicLong();
        try (var highlighter = new WebSocketHighlighter(clock::get, 2, Duration.ofSeconds(10))) {
            highlighter.rememberUpgrade(upgrade(1, "a", "/chat", false), HighlightColor.RED, "One");
            highlighter.rememberUpgrade(upgrade(2, "b", "/chat", false), HighlightColor.BLUE, "Two");
            highlighter.rememberUpgrade(upgrade(3, "c", "/chat", false), HighlightColor.GREEN, "Three");
            assertNull(open(highlighter, upgrade(9, "c", "/chat", false)).handler.get());
            clock.set(Duration.ofSeconds(10).toNanos());
            assertNull(open(highlighter, upgrade(9, "a", "/chat", false)).handler.get());
            highlighter.rememberUpgrade(upgrade(4, "d", "/chat", false), HighlightColor.GREEN, "Four");
            assertLabel(open(highlighter, upgrade(9, "d", "/chat", false)), HighlightColor.GREEN, "Four");
        }
    }

    @Test
    void duplicateAtCapacityStillPoisonsTheExistingCandidate() {
        try (var highlighter = new WebSocketHighlighter(System::nanoTime, 1, Duration.ofMinutes(5))) {
            highlighter.rememberUpgrade(upgrade(1, "a", "/chat", false), HighlightColor.RED, "One");
            highlighter.rememberUpgrade(upgrade(2, "a", "/chat", false), null, null);
            assertNull(open(highlighter, upgrade(9, "a", "/chat", false)).handler.get());
        }
    }

    @Test
    void rejectedHandshakesCannotBorrowALaterCandidatesAttribution() {
        try (var highlighter = new WebSocketHighlighter(System::nanoTime, 1, Duration.ofMinutes(5))) {
            var first = upgrade(1, "a", "/chat", false);
            var rejected = upgrade(2, "b", "/chat", false);
            highlighter.rememberUpgrade(first, HighlightColor.RED, "One");
            highlighter.rememberUpgrade(rejected, null, null);
            assertLabel(open(highlighter, first), HighlightColor.RED, "One");
            highlighter.rememberUpgrade(upgrade(3, "b", "/chat", false), HighlightColor.BLUE, "Two");
            assertNull(open(highlighter, rejected).handler.get());
        }
    }

    @Test
    void rejectedHandshakeEditsCannotBorrowAnExistingCandidatesAttribution() {
        try (var highlighter = new WebSocketHighlighter(System::nanoTime, 1, Duration.ofMinutes(5))) {
            var first = upgrade(1, "a", "/chat", false);
            highlighter.rememberUpgrade(first, HighlightColor.RED, "One");
            highlighter.rememberUpgrade(upgrade(2, "b", "/chat", false), null, null);
            var edited = upgrade(2, "a", "/chat", false);
            highlighter.observeUpgradeToBeSent(edited);
            assertNull(open(highlighter, edited).handler.get());
            assertNull(open(highlighter, first).handler.get());
        }
    }

    @Test
    void expiredHandshakesCannotBorrowALaterCandidatesAttribution() {
        AtomicLong clock = new AtomicLong();
        try (var highlighter = new WebSocketHighlighter(clock::get, 2, Duration.ofSeconds(10))) {
            var expired = upgrade(1, "key", "/chat", false);
            highlighter.rememberUpgrade(expired, null, null);
            clock.set(Duration.ofSeconds(10).toNanos());
            var next = upgrade(2, "key", "/chat", false);
            highlighter.rememberUpgrade(next, HighlightColor.BLUE, "Two");
            assertNull(open(highlighter, expired).handler.get());
            assertNull(open(highlighter, next).handler.get());
        }
    }

    @Test
    void expiredAmbiguityCannotBecomeASafeMatchAgain() {
        AtomicLong clock = new AtomicLong();
        try (var highlighter = new WebSocketHighlighter(clock::get, 2, Duration.ofSeconds(10))) {
            highlighter.rememberUpgrade(upgrade(1, "key", "/chat", false), HighlightColor.RED, "One");
            highlighter.rememberUpgrade(upgrade(2, "key", "/chat", false), null, null);
            clock.set(Duration.ofSeconds(10).toNanos());
            highlighter.rememberUpgrade(upgrade(3, "key", "/chat", false), HighlightColor.BLUE, "Two");
            assertNull(open(highlighter, upgrade(9, "key", "/chat", false)).handler.get());
        }
    }

    @Test
    void aRemovedUpgradeCannotLeaveAStaleCandidate() {
        try (var highlighter = new WebSocketHighlighter()) {
            highlighter.rememberUpgrade(upgrade(1, "key", "/chat", false), HighlightColor.RED, "Work");
            var sent = upgrade(1, "key", "/chat", false);
            when(sent.headers()).thenReturn(List.of());
            highlighter.observeUpgradeToBeSent(sent);
            assertNull(open(highlighter, upgrade(9, "key", "/chat", false)).handler.get());
        }
    }

    @ParameterizedTest
    @EnumSource(Direction.class)
    void textMessagesKeepTheirPayloadAndInterceptionDecision(Direction direction) {
        try (var highlighter = new WebSocketHighlighter();
             var received = mockStatic(TextMessageReceivedAction.class);
             var sent = mockStatic(TextMessageToBeSentAction.class)) {
            highlighter.rememberUpgrade(upgrade(1, "key", "/chat", false), HighlightColor.RED, "Work");
            var handler = open(highlighter, upgrade(9, "key", "/chat", false)).handler.get();
            var notes = new Notes();
            var message = text(notes);
            when(message.direction()).thenReturn(direction);
            String payload = "{\"value\":\"original\"}";
            when(message.payload()).thenReturn(payload);
            var receivedAction = mock(TextMessageReceivedAction.class);
            var sentAction = mock(TextMessageToBeSentAction.class);
            received.when(() -> TextMessageReceivedAction.continueWith(payload)).thenReturn(receivedAction);
            sent.when(() -> TextMessageToBeSentAction.continueWith(payload)).thenReturn(sentAction);
            assertSame(receivedAction, handler.handleTextMessageReceived(message));
            assertEquals(HighlightColor.RED, notes.color);
            assertEquals("Work", notes.note);
            notes.color = HighlightColor.GREEN;
            notes.note = "My edited note";
            assertSame(sentAction, handler.handleTextMessageToBeSent(message));
            assertEquals(HighlightColor.GREEN, notes.color);
            assertEquals("My edited note", notes.note);
        }
    }

    @ParameterizedTest
    @EnumSource(Direction.class)
    void binaryMessagesKeepTheExactPayload(Direction direction) {
        try (var highlighter = new WebSocketHighlighter();
             var received = mockStatic(BinaryMessageReceivedAction.class);
             var sent = mockStatic(BinaryMessageToBeSentAction.class)) {
            highlighter.rememberUpgrade(upgrade(1, "key", "/chat", true), HighlightColor.BLUE, "Admin");
            var handler = open(highlighter, upgrade(9, "key", "/chat", true)).handler.get();
            Notes notes = new Notes();
            var message = mock(InterceptedBinaryMessage.class);
            ByteArray payload = mock(ByteArray.class);
            when(message.payload()).thenReturn(payload);
            when(message.annotations()).thenReturn(notes);
            when(message.direction()).thenReturn(direction);
            var receivedAction = mock(BinaryMessageReceivedAction.class);
            var sentAction = mock(BinaryMessageToBeSentAction.class);
            received.when(() -> BinaryMessageReceivedAction.continueWith(payload)).thenReturn(receivedAction);
            sent.when(() -> BinaryMessageToBeSentAction.continueWith(payload)).thenReturn(sentAction);
            assertSame(receivedAction, handler.handleBinaryMessageReceived(message));
            assertEquals(HighlightColor.BLUE, notes.color);
            assertEquals("Admin", notes.note);
            assertSame(sentAction, handler.handleBinaryMessageToBeSent(message));
        }
    }

    @Test
    void preservesUserNotesAndSupportsNameOnlyAndLegacyColorOnly() {
        try (var highlighter = new WebSocketHighlighter()) {
            highlighter.rememberUpgrade(upgrade(1, "a", "/chat", false), null, "Toolbar");
            assertLabel(open(highlighter, upgrade(9, "a", "/chat", false)), null, "Toolbar");
            highlighter.rememberUpgrade(upgrade(2, "b", "/chat", false), HighlightColor.BLUE, null);
            assertLabel(open(highlighter, upgrade(9, "b", "/chat", false)), HighlightColor.BLUE, "");
            highlighter.rememberUpgrade(upgrade(3, "c", "/chat", false), HighlightColor.RED, "Work");
            Notes notes = new Notes();
            notes.note = "Investigate auth";
            try (var actions = mockStatic(TextMessageReceivedAction.class)) {
                open(highlighter, upgrade(9, "c", "/chat", false)).handler.get().handleTextMessageReceived(text(notes));
            }
            assertEquals("Investigate auth", notes.note);
            assertEquals(HighlightColor.RED, notes.color);
        }
    }

    @Test
    void closeDeregistersHandlersAndLeavesUserConnectionsOpen() {
        var highlighter = new WebSocketHighlighter();
        highlighter.rememberUpgrade(upgrade(1, "a", "/chat", false), HighlightColor.RED, "Work");
        var wire = open(highlighter, upgrade(9, "a", "/chat", false));
        highlighter.close();
        highlighter.close();
        verify(wire.registration).deregister();
        verify(wire.socket, never()).close();
        assertNull(open(highlighter, upgrade(99, "a", "/chat", false)).handler.get());
        try (var actions = mockStatic(TextMessageReceivedAction.class)) {
            Notes notes = new Notes();
            wire.handler.get().handleTextMessageReceived(text(notes));
            assertNull(notes.color);
            assertEquals("", notes.note);
        }
    }

    @Test
    void closedConnectionsReleaseTheirRegistrationOnce() {
        try (var highlighter = new WebSocketHighlighter()) {
            highlighter.rememberUpgrade(upgrade(1, "a", "/chat", false), HighlightColor.RED, "Work");
            var wire = open(highlighter, upgrade(9, "a", "/chat", false));
            wire.handler.get().onClose();
            highlighter.close();
            verify(wire.registration).deregister();
            verify(wire.socket, never()).close();
        }
    }

    @Test
    void unloadDoesNotWaitForRegistrationAndLateHandlersAreInactive() throws Exception {
        var highlighter = new WebSocketHighlighter();
        highlighter.rememberUpgrade(upgrade(1, "a", "/chat", false), HighlightColor.RED, "Work");
        Wire wire = new Wire(upgrade(9, "a", "/chat", false));
        CountDownLatch registering = new CountDownLatch(1);
        CountDownLatch resume = new CountDownLatch(1);
        doAnswer(call -> {
            wire.handler.set(call.getArgument(0));
            registering.countDown();
            assertTrue(resume.await(3, TimeUnit.SECONDS));
            return wire.registration;
        }).when(wire.socket).registerProxyMessageHandler(any());
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            Future<?> creation = worker.submit(() -> highlighter.handleWebSocketCreation(wire.creation));
            assertTrue(registering.await(3, TimeUnit.SECONDS));
            assertTimeoutPreemptively(Duration.ofSeconds(1), highlighter::close);
            try (var actions = mockStatic(TextMessageReceivedAction.class)) {
                Notes notes = new Notes();
                wire.handler.get().handleTextMessageReceived(text(notes));
                assertNull(notes.color);
            }
            resume.countDown();
            creation.get(3, TimeUnit.SECONDS);
            verify(wire.registration).deregister();
        } finally {
            resume.countDown();
            highlighter.close();
            worker.shutdownNow();
        }
    }

    static InterceptedRequest upgrade(int id, String key, String path, boolean secure) {
        var request = mock(InterceptedRequest.class);
        var service = mock(HttpService.class);
        when(service.host()).thenReturn("example.test");
        when(service.port()).thenReturn(secure ? 443 : 80);
        when(service.secure()).thenReturn(secure);
        when(request.httpService()).thenReturn(service);
        when(request.path()).thenReturn(path);
        when(request.method()).thenReturn("GET");
        when(request.messageId()).thenReturn(id);
        var headers = List.of(header("uPgRaDe", " WebSocket "),
                header("cOnNeCtIoN", "keep-alive, Upgrade"), header("Sec-WebSocket-Key", key));
        when(request.headers()).thenReturn(headers);
        return request;
    }

    private static HttpHeader header(String name, String value) {
        var header = mock(HttpHeader.class);
        when(header.name()).thenReturn(name);
        when(header.value()).thenReturn(value);
        return header;
    }

    static Wire open(WebSocketHighlighter highlighter, HttpRequest request) {
        Wire wire = new Wire(request);
        highlighter.handleWebSocketCreation(wire.creation);
        return wire;
    }

    static void assertLabel(Wire wire, HighlightColor color, String name) {
        assertNotNull(wire.handler.get(), "a matched connection must get a handler");
        Notes notes = new Notes();
        try (var actions = mockStatic(TextMessageReceivedAction.class)) {
            wire.handler.get().handleTextMessageReceived(text(notes));
        }
        assertEquals(color, notes.color);
        assertEquals(name, notes.note);
    }

    private static InterceptedTextMessage text(Notes notes) {
        var message = mock(InterceptedTextMessage.class);
        when(message.annotations()).thenReturn(notes);
        when(message.payload()).thenReturn("unchanged");
        return message;
    }

    static final class Wire {
        final ProxyWebSocket socket = mock(ProxyWebSocket.class);
        final ProxyWebSocketCreation creation = mock(ProxyWebSocketCreation.class);
        final Registration registration = mock(Registration.class);
        final AtomicReference<ProxyMessageHandler> handler = new AtomicReference<>();
        Wire(HttpRequest request) {
            when(creation.upgradeRequest()).thenReturn(request);
            when(creation.proxyWebSocket()).thenReturn(socket);
            when(socket.registerProxyMessageHandler(any())).thenAnswer(call -> {
                handler.set(call.getArgument(0));
                return registration;
            });
        }
    }

    static final class Notes implements Annotations {
        String note = "";
        HighlightColor color;
        public String notes() { return note; }
        public boolean hasNotes() { return !note.isEmpty(); }
        public boolean hasHighlightColor() { return color != null; }
        public void setNotes(String value) { note = value; }
        public HighlightColor highlightColor() { return color; }
        public void setHighlightColor(HighlightColor value) { color = value; }
        public Annotations withNotes(String value) { Notes copy = copy(); copy.note = value; return copy; }
        public Annotations withHighlightColor(HighlightColor value) { Notes copy = copy(); copy.color = value; return copy; }
        private Notes copy() { Notes copy = new Notes(); copy.note = note; copy.color = color; return copy; }
    }
}
