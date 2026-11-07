package burp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.MalformedRequestException;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.*;

class MalformedRequestTest {
    @Test
    void malformedMethodShouldNotPreventPairedHttpAnnotation() {
        var highlighter = paired();
        var request = WebSocketHighlighterTest.upgrade(700, "key", "/chat", false);
        when(request.listenerInterface()).thenReturn("127.0.0.1:18080");
        when(request.method()).thenThrow(new MalformedRequestException("invalid request line"));
        when(request.headers()).thenReturn(List.of());
        var notes = new WebSocketHighlighterTest.Notes();
        when(request.annotations()).thenReturn(notes);
        try (var actions = mockStatic(ProxyRequestReceivedAction.class)) {
            assertDoesNotThrow(() -> highlighter.handleRequestReceived(request));
        }
    }

    @Test
    void malformedPathShouldNotPreventPairedHttpAnnotation() {
        var highlighter = paired();
        var request = WebSocketHighlighterTest.upgrade(701, "key", "/chat", false);
        when(request.listenerInterface()).thenReturn("127.0.0.1:18080");
        when(request.path()).thenThrow(new MalformedRequestException("invalid request target"));
        var notes = new WebSocketHighlighterTest.Notes();
        when(request.annotations()).thenReturn(notes);
        try (var actions = mockStatic(ProxyRequestReceivedAction.class)) {
            assertDoesNotThrow(() -> highlighter.handleRequestReceived(request));
        }
    }

    @Test
    void malformedMethodShouldNotPreventLegacyProxyCleaning() {
        var highlighter = new ContainerHighlighter(false);
        var request = mock(InterceptedRequest.class);
        var header = mock(HttpHeader.class);
        when(header.name()).thenReturn("X-MAC-Container-Color");
        when(header.value()).thenReturn("red");
        when(request.headers()).thenReturn(List.of(header));
        when(request.method()).thenThrow(new MalformedRequestException("invalid request line"));
        var notes = new WebSocketHighlighterTest.Notes();
        when(request.annotations()).thenReturn(notes);
        var clean = mock(HttpRequest.class);
        when(request.withRemovedHeader("X-MAC-Container-Color")).thenReturn(clean);
        try (var actions = mockStatic(ProxyRequestReceivedAction.class)) {
            assertDoesNotThrow(() -> highlighter.handleRequestReceived(request));
        }
        try (var actions = mockStatic(ProxyRequestToBeSentAction.class)) {
            assertDoesNotThrow(() -> highlighter.handleRequestToBeSent(request));
        }
    }

    private static ContainerHighlighter paired() {
        var highlighter = new ContainerHighlighter(false);
        highlighter.setPairedCheck(() -> true);
        highlighter.registry().replace(Map.of(ListenerAddress.parse("127.0.0.1:18080"),
                new ContainerRegistry.Container("one", "Work", "red")), Map.of());
        return highlighter;
    }
}
