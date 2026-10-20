package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.repeater.Repeater;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class ContainerHighlighterTest {

    /** The canonical casing PhoenixBox sends, which is not the lower-case form we match against. */
    private static final String COLOR_HEADER = "X-MAC-Container-Color";
    private static final String NAME_HEADER = "X-MAC-Container-Name";

    // ---- Legacy mode: not paired, so PhoenixBox marks requests with the colour header -----------

    @Test
    void legacyColoursFromTheHeaderStripsItAndWritesNoNote() {
        ContainerHighlighter highlighter = new ContainerHighlighter(false);

        Annotations annotations = selfAnnotations();
        InterceptedRequest request = mock(InterceptedRequest.class);
        HttpRequest clean = mock(HttpRequest.class);
        stubHeaders(request, " Blue ", null);
        when(request.annotations()).thenReturn(annotations);
        when(request.withRemovedHeader(COLOR_HEADER)).thenReturn(clean);

        try (MockedStatic<ProxyRequestReceivedAction> actions = mockStatic(ProxyRequestReceivedAction.class)) {
            ProxyRequestReceivedAction action = mock(ProxyRequestReceivedAction.class);
            actions.when(() -> ProxyRequestReceivedAction.continueWith(clean, annotations)).thenReturn(action);

            assertSame(action, highlighter.handleRequestReceived(request));
        }

        verify(annotations).withHighlightColor(HighlightColor.BLUE);
        verify(annotations, never()).withNotes(anyString());
    }

    @Test
    void legacyAlsoStripsANameHeaderAnythingElseSent() {
        ContainerHighlighter highlighter = new ContainerHighlighter(false);

        Annotations annotations = selfAnnotations();
        InterceptedRequest request = mock(InterceptedRequest.class);
        HttpRequest withoutColor = mock(HttpRequest.class);
        HttpRequest clean = mock(HttpRequest.class);
        stubHeaders(request, "red", "Attacker");
        when(request.annotations()).thenReturn(annotations);
        when(request.withRemovedHeader(COLOR_HEADER)).thenReturn(withoutColor);
        when(withoutColor.withRemovedHeader(NAME_HEADER)).thenReturn(clean);

        try (MockedStatic<ProxyRequestReceivedAction> actions = mockStatic(ProxyRequestReceivedAction.class)) {
            highlighter.handleRequestReceived(request);
            actions.verify(() -> ProxyRequestReceivedAction.continueWith(clean, annotations));
        }
        verify(annotations, never()).withNotes(anyString());
    }

    @Test
    void legacyLeavesRequestsWithoutTheHeaderAlone() {
        ContainerHighlighter highlighter = new ContainerHighlighter(false);

        InterceptedRequest request = mock(InterceptedRequest.class);
        HttpHeader host = header("Host", "example.com");
        when(request.headers()).thenReturn(List.of(host));

        try (MockedStatic<ProxyRequestReceivedAction> actions = mockStatic(ProxyRequestReceivedAction.class)) {
            highlighter.handleRequestReceived(request);
            actions.verify(() -> ProxyRequestReceivedAction.continueWith(request));
        }
        verify(request, never()).withRemovedHeader(anyString());
    }

    @Test
    void legacyStripsAnUnrecognisedColourButDoesNotHighlightIt() {
        ContainerHighlighter highlighter = new ContainerHighlighter(false);

        Annotations annotations = selfAnnotations();
        InterceptedRequest request = mock(InterceptedRequest.class);
        HttpRequest clean = mock(HttpRequest.class);
        stubHeaders(request, "chartreuse", null);
        when(request.annotations()).thenReturn(annotations);
        when(request.withRemovedHeader(COLOR_HEADER)).thenReturn(clean);

        try (MockedStatic<ProxyRequestReceivedAction> actions = mockStatic(ProxyRequestReceivedAction.class)) {
            highlighter.handleRequestReceived(request);
            actions.verify(() -> ProxyRequestReceivedAction.continueWith(clean, annotations));
        }
        verify(annotations, never()).withHighlightColor(any());
    }

    @Test
    void legacyStripsAtTheSendStageAndForEveryTool() {
        ContainerHighlighter highlighter = new ContainerHighlighter(false);

        Annotations annotations = selfAnnotations();
        InterceptedRequest proxied = mock(InterceptedRequest.class);
        HttpRequest cleanProxied = mock(HttpRequest.class);
        stubHeaders(proxied, "red", null);
        when(proxied.annotations()).thenReturn(annotations);
        when(proxied.withRemovedHeader(COLOR_HEADER)).thenReturn(cleanProxied);

        HttpRequestToBeSent tool = mock(HttpRequestToBeSent.class);
        HttpRequest cleanTool = mock(HttpRequest.class);
        stubHeaders(tool, "red", null);
        when(tool.withRemovedHeader(COLOR_HEADER)).thenReturn(cleanTool);

        try (MockedStatic<ProxyRequestToBeSentAction> proxyActions = mockStatic(ProxyRequestToBeSentAction.class);
             MockedStatic<RequestToBeSentAction> toolActions = mockStatic(RequestToBeSentAction.class)) {
            highlighter.handleRequestToBeSent(proxied);
            highlighter.handleHttpRequestToBeSent(tool);
            proxyActions.verify(() -> ProxyRequestToBeSentAction.continueWith(cleanProxied, annotations));
            toolActions.verify(() -> RequestToBeSentAction.continueWith(cleanTool));
        }
    }

    // ---- Paired mode: PhoenixBox sends no headers, so none are read or stripped ------------------

    @Test
    void pairedPassesRequestsThroughUntouched() {
        ContainerHighlighter highlighter = new ContainerHighlighter(false);
        highlighter.setPairedCheck(() -> true);

        InterceptedRequest proxied = mock(InterceptedRequest.class);
        HttpRequestToBeSent tool = mock(HttpRequestToBeSent.class);
        stubHeaders(proxied, "red", null);
        stubHeaders(tool, "red", null);

        try (MockedStatic<ProxyRequestReceivedAction> received = mockStatic(ProxyRequestReceivedAction.class);
             MockedStatic<ProxyRequestToBeSentAction> toBeSent = mockStatic(ProxyRequestToBeSentAction.class);
             MockedStatic<RequestToBeSentAction> toolActions = mockStatic(RequestToBeSentAction.class)) {
            highlighter.handleRequestReceived(proxied);
            highlighter.handleRequestToBeSent(proxied);
            highlighter.handleHttpRequestToBeSent(tool);

            received.verify(() -> ProxyRequestReceivedAction.continueWith(proxied));
            toBeSent.verify(() -> ProxyRequestToBeSentAction.continueWith(proxied));
            toolActions.verify(() -> RequestToBeSentAction.continueWith(tool));
        }
        verify(proxied, never()).withRemovedHeader(anyString());
        verify(proxied, never()).annotations();
        verify(tool, never()).withRemovedHeader(anyString());
    }

    // ---- Traffic on a container's listener -------------------------------------------------------

    @Test
    void highlightsAndNamesTrafficFromAContainerListenerWithoutChangingIt() {
        ContainerHighlighter highlighter = listening("Work", "red");
        highlighter.setPairedCheck(() -> true);

        Annotations annotations = selfAnnotations();
        InterceptedRequest request = mock(InterceptedRequest.class);
        when(request.listenerInterface()).thenReturn("127.0.0.1:18080");
        when(request.annotations()).thenReturn(annotations);

        try (MockedStatic<ProxyRequestReceivedAction> actions = mockStatic(ProxyRequestReceivedAction.class)) {
            ProxyRequestReceivedAction action = mock(ProxyRequestReceivedAction.class);
            actions.when(() -> ProxyRequestReceivedAction.continueWith(request, annotations)).thenReturn(action);

            assertSame(action, highlighter.handleRequestReceived(request));
        }

        verify(annotations).withHighlightColor(HighlightColor.RED);
        // The note is the bare name: the highlight already shows the colour.
        verify(annotations).withNotes("Work");
        verify(request, never()).withRemovedHeader(anyString());
    }

    @Test
    void keepsTheUsersNoteOnContainerListenerTraffic() {
        ContainerHighlighter highlighter = listening("Work", "blue");

        Annotations annotations = selfAnnotations();
        when(annotations.hasNotes()).thenReturn(true);
        InterceptedRequest request = mock(InterceptedRequest.class);
        when(request.listenerInterface()).thenReturn("127.0.0.1:18080");
        when(request.annotations()).thenReturn(annotations);

        try (MockedStatic<ProxyRequestReceivedAction> ignored = mockStatic(ProxyRequestReceivedAction.class)) {
            highlighter.handleRequestReceived(request);
        }

        verify(annotations).withHighlightColor(HighlightColor.BLUE);
        verify(annotations, never()).withNotes(anyString());
    }

    // ---- Repeater ---------------------------------------------------------------------------------

    @Test
    void offersRepeaterForANoteItWroteAndNumbersTheTabs() {
        Repeater repeater = mock(Repeater.class);
        ContainerHighlighter highlighter = new ContainerHighlighter(false);
        highlighter.initialize(apiWith(mock(Logging.class), repeater));
        highlighter.knownNames().addAll(List.of("Work", "Admin"));

        HttpRequest first = mock(HttpRequest.class);
        HttpRequest second = mock(HttpRequest.class);
        clickMenuItem(highlighter, contextMenuEventFor(notedRequestResponse(first, "Work")));
        clickMenuItem(highlighter, contextMenuEventFor(notedRequestResponse(second, "Admin")));

        verify(repeater).sendToRepeater(first, "1 Work");
        verify(repeater).sendToRepeater(second, "2 Admin");
    }

    @Test
    void ignoresNotesThatAreNotContainerNames() {
        ContainerHighlighter highlighter = new ContainerHighlighter(false);
        highlighter.initialize(apiWith(mock(Logging.class), mock(Repeater.class)));
        highlighter.knownNames().addAll(List.of("Work"));

        assertTrue(highlighter.provideMenuItems(
                contextMenuEventFor(notedRequestResponse(mock(HttpRequest.class), "my own note"))).isEmpty());
        assertTrue(highlighter.provideMenuItems(
                contextMenuEventFor(notedRequestResponse(mock(HttpRequest.class), "🔴 Work"))).isEmpty());
    }

    // ---- Misc -------------------------------------------------------------------------------------

    @Test
    void showsItsReleaseVersionInBurp() {
        Logging logging = mock(Logging.class);
        MontoyaApi api = apiWith(logging);
        new ContainerHighlighter(false).initialize(api);

        String version = ContainerHighlighter.VERSION;
        assertTrue(version.matches("\\d+\\.\\d+\\.\\d+"), "version comes from the build, got: " + version);
        verify(api.extension()).setName("PhoenixBox Highlighter v" + version);
        verify(logging).logToOutput("PhoenixBox Highlighter v" + version + " loaded");
    }

    @Test
    void reportsEachUnrecognizedColorValueOnlyOnceAndTruncatesIt() {
        Logging logging = mock(Logging.class);
        ContainerHighlighter highlighter = new ContainerHighlighter(false);
        highlighter.initialize(apiWith(logging));

        for (String value : new String[]{"chartreuse", "chartreuse", "x".repeat(10_000)}) {
            InterceptedRequest request = mock(InterceptedRequest.class);
            HttpRequest clean = mock(HttpRequest.class);
            stubHeaders(request, value, null);
            Annotations annotations = selfAnnotations();
            when(request.annotations()).thenReturn(annotations);
            when(request.withRemovedHeader(COLOR_HEADER)).thenReturn(clean);
            try (MockedStatic<ProxyRequestReceivedAction> ignored = mockStatic(ProxyRequestReceivedAction.class)) {
                highlighter.handleRequestReceived(request);
            }
        }

        ArgumentCaptor<String> messages = ArgumentCaptor.forClass(String.class);
        verify(logging, times(2)).logToError(messages.capture());
        assertTrue(messages.getAllValues().get(0).contains("chartreuse"));
        String truncated = messages.getAllValues().get(1);
        assertTrue(truncated.length() < 300 && truncated.contains("xxx…"), truncated);
    }

    // ---- Helpers ----------------------------------------------------------------------------------

    private static ContainerHighlighter listening(String name, String color) {
        ContainerHighlighter highlighter = new ContainerHighlighter(false);
        highlighter.registry().replace(
                Map.of(ListenerAddress.parse("127.0.0.1:18080"),
                        new ContainerRegistry.Container("firefox-container-1", name, color)),
                Map.of());
        return highlighter;
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        when(header.name()).thenReturn(name);
        when(header.value()).thenReturn(value);
        return header;
    }

    /** Stubs {@code headers()}, which is the only header source the extension reads. */
    private static void stubHeaders(HttpRequest request, String colorValue, String nameValue) {
        List<HttpHeader> headers = new ArrayList<>();
        if (colorValue != null) {
            headers.add(header(COLOR_HEADER, colorValue));
        }
        if (nameValue != null) {
            headers.add(header(NAME_HEADER, nameValue));
        }
        when(request.headers()).thenReturn(headers);
    }

    /** An {@link Annotations} mock that returns itself from every builder, so chaining is stable. */
    private static Annotations selfAnnotations() {
        Annotations annotations = mock(Annotations.class);
        when(annotations.withHighlightColor(any())).thenReturn(annotations);
        when(annotations.withNotes(anyString())).thenReturn(annotations);
        when(annotations.hasNotes()).thenReturn(false);
        return annotations;
    }

    private static HttpRequestResponse notedRequestResponse(HttpRequest request, String note) {
        Annotations annotations = mock(Annotations.class);
        when(annotations.hasNotes()).thenReturn(true);
        when(annotations.notes()).thenReturn(note);

        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(request);
        when(requestResponse.annotations()).thenReturn(annotations);
        return requestResponse;
    }

    private static ContextMenuEvent contextMenuEventFor(HttpRequestResponse requestResponse) {
        MessageEditorHttpRequestResponse editor = mock(MessageEditorHttpRequestResponse.class);
        when(editor.requestResponse()).thenReturn(requestResponse);

        ContextMenuEvent event = mock(ContextMenuEvent.class);
        when(event.messageEditorRequestResponse()).thenReturn(Optional.of(editor));
        return event;
    }

    private static void clickMenuItem(ContainerHighlighter highlighter, ContextMenuEvent event) {
        List<Component> items = highlighter.provideMenuItems(event);
        assertEquals(1, items.size());

        JMenuItem item = (JMenuItem) items.get(0);
        for (ActionListener listener : item.getActionListeners()) {
            listener.actionPerformed(new ActionEvent(item, ActionEvent.ACTION_PERFORMED, ""));
        }
    }

    private static MontoyaApi apiWith(Logging logging) {
        return apiWith(logging, mock(Repeater.class));
    }

    private static MontoyaApi apiWith(Logging logging, Repeater repeater) {
        MontoyaApi api = mock(MontoyaApi.class);
        when(api.logging()).thenReturn(logging);
        when(api.extension()).thenReturn(mock(Extension.class));
        when(api.proxy()).thenReturn(mock(Proxy.class));
        when(api.http()).thenReturn(mock(Http.class));
        when(api.repeater()).thenReturn(repeater);
        when(api.userInterface()).thenReturn(mock(UserInterface.class));
        return api;
    }
}
