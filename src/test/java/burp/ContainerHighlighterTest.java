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
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class ContainerHighlighterTest {

    /** The canonical casing PhoenixBox sends, which is not the lower-case form we match against. */
    private static final String COLOR_HEADER = "X-Mac-Container-Color";
    private static final String NAME_HEADER = "X-Mac-Container-Name";

    /**
     * Shared wire-format vectors: {decoded name, value as it arrives on the header}. PhoenixBox
     * keeps the same table and asserts the encode direction, so both halves of the contract are
     * pinned to identical values rather than to prose.
     *
     * Keep in sync with NAME_VECTORS in PhoenixBox test/request-header-helpers.test.js, with one
     * deliberate exception: that table also carries a CR/LF vector, which cannot round-trip here
     * because control characters are stripped out of tab labels. See
     * {@link #keepsControlCharactersOutOfRepeaterTabNames()} instead.
     */
    private static final String[][] CONTAINER_NAME_VECTORS = {
            {"Attacker", "Attacker"},
            {"Admin Account", "Admin%20Account"},
            // encodeURIComponent leaves "+" literal while URLDecoder would read it as a space;
            // this vector is what pins the decoder choice on this side.
            {"C++", "C%2B%2B"},
            {"50%", "50%25"},
            {"אבטחה", "%D7%90%D7%91%D7%98%D7%97%D7%94"},
            {"🔥", "%F0%9F%94%A5"},
    };

    @Test
    void colorsStripsAndNotesAtReceiveStage() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        Annotations annotations = selfAnnotations();
        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
        HttpRequest withoutColor = mock(HttpRequest.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        stubHeaders(interceptedRequest, " Blue ", "Attacker");
        when(interceptedRequest.annotations()).thenReturn(annotations);
        when(interceptedRequest.withRemovedHeader(COLOR_HEADER)).thenReturn(withoutColor);
        when(withoutColor.withRemovedHeader(NAME_HEADER)).thenReturn(cleanRequest);

        ProxyRequestReceivedAction expectedAction = mock(ProxyRequestReceivedAction.class);
        try (MockedStatic<ProxyRequestReceivedAction> receivedActionStatic = mockStatic(ProxyRequestReceivedAction.class)) {
            receivedActionStatic.when(() -> ProxyRequestReceivedAction.continueWith(cleanRequest, annotations))
                                .thenReturn(expectedAction);

            assertSame(expectedAction, highlighter.handleRequestReceived(interceptedRequest));
        }

        // Both headers gone, the request coloured, and the container recorded as a note so it
        // survives into HTTP history and the Send-to-Repeater action.
        verify(interceptedRequest).withRemovedHeader(COLOR_HEADER);
        verify(withoutColor).withRemovedHeader(NAME_HEADER);
        verify(annotations).withHighlightColor(HighlightColor.BLUE);
        verify(annotations).withNotes("🔵 Attacker");
    }

    // The headers arrive canonically cased, but we match on a lower-case constant.
    @Test
    void matchesHeaderNamesRegardlessOfCasing() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        Annotations annotations = selfAnnotations();
        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        List<HttpHeader> shoutedHeaders = List.of(header("X-MAC-CONTAINER-COLOR", "red"));
        when(interceptedRequest.headers()).thenReturn(shoutedHeaders);
        when(interceptedRequest.annotations()).thenReturn(annotations);
        when(interceptedRequest.withRemovedHeader("X-MAC-CONTAINER-COLOR")).thenReturn(cleanRequest);

        try (MockedStatic<ProxyRequestReceivedAction> receivedActionStatic = mockStatic(ProxyRequestReceivedAction.class)) {
            receivedActionStatic.when(() -> ProxyRequestReceivedAction.continueWith(cleanRequest, annotations))
                                .thenReturn(mock(ProxyRequestReceivedAction.class));

            highlighter.handleRequestReceived(interceptedRequest);
        }

        verify(interceptedRequest).withRemovedHeader("X-MAC-CONTAINER-COLOR");
        verify(annotations).withHighlightColor(HighlightColor.RED);
    }

    @Test
    void notesTheColourWhenNoNameHeaderIsPresent() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        Annotations annotations = selfAnnotations();
        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        stubHeaders(interceptedRequest, "red", null);
        when(interceptedRequest.annotations()).thenReturn(annotations);
        when(interceptedRequest.withRemovedHeader(COLOR_HEADER)).thenReturn(cleanRequest);

        try (MockedStatic<ProxyRequestReceivedAction> receivedActionStatic = mockStatic(ProxyRequestReceivedAction.class)) {
            receivedActionStatic.when(() -> ProxyRequestReceivedAction.continueWith(cleanRequest, annotations))
                                .thenReturn(mock(ProxyRequestReceivedAction.class));

            highlighter.handleRequestReceived(interceptedRequest);
        }

        verify(annotations).withNotes("🔴 red");
    }

    @Test
    void doesNotClobberANoteTheUserAlreadyWrote() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        Annotations annotations = selfAnnotations();
        when(annotations.hasNotes()).thenReturn(true);

        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        stubHeaders(interceptedRequest, "red", null);
        when(interceptedRequest.annotations()).thenReturn(annotations);
        when(interceptedRequest.withRemovedHeader(COLOR_HEADER)).thenReturn(cleanRequest);

        try (MockedStatic<ProxyRequestReceivedAction> receivedActionStatic = mockStatic(ProxyRequestReceivedAction.class)) {
            receivedActionStatic.when(() -> ProxyRequestReceivedAction.continueWith(cleanRequest, annotations))
                                .thenReturn(mock(ProxyRequestReceivedAction.class));

            highlighter.handleRequestReceived(interceptedRequest);
        }

        verify(annotations, never()).withNotes(anyString());
    }

    @Test
    void stripsAtReceiveEvenWhenColorIsUnrecognized() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        Annotations annotations = selfAnnotations();
        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        stubHeaders(interceptedRequest, "chartreuse", null);
        when(interceptedRequest.annotations()).thenReturn(annotations);
        when(interceptedRequest.withRemovedHeader(COLOR_HEADER)).thenReturn(cleanRequest);

        try (MockedStatic<ProxyRequestReceivedAction> receivedActionStatic = mockStatic(ProxyRequestReceivedAction.class)) {
            receivedActionStatic.when(() -> ProxyRequestReceivedAction.continueWith(cleanRequest, annotations))
                                .thenReturn(mock(ProxyRequestReceivedAction.class));

            highlighter.handleRequestReceived(interceptedRequest);
        }

        verify(annotations, never()).withHighlightColor(any());
        // The colour is unknown, but it is still a value, so it is still noted — under the
        // neutral marker, since there is no colour to show.
        verify(annotations).withNotes("⚪ chartreuse");
    }

    /**
     * Every colour PhoenixBox can send must map to its own marker. A colour that fell through to the
     * neutral one, or shared a marker with another colour, would make the Notes column ambiguous —
     * which is the whole point of the colour cue.
     */
    @Test
    void givesEverySupportedColourItsOwnDistinctMarker() {
        List<String> colors = List.of("blue", "cyan", "green", "yellow", "orange", "red", "pink", "magenta");
        List<String> markersSeen = new ArrayList<>();

        for (String color : colors) {
            ContainerHighlighter highlighter = new ContainerHighlighter();

            Annotations annotations = selfAnnotations();
            InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
            HttpRequest cleanRequest = mock(HttpRequest.class);
            stubHeaders(interceptedRequest, color, null);
            when(interceptedRequest.annotations()).thenReturn(annotations);
            when(interceptedRequest.withRemovedHeader(COLOR_HEADER)).thenReturn(cleanRequest);

            try (MockedStatic<ProxyRequestReceivedAction> receivedActionStatic = mockStatic(ProxyRequestReceivedAction.class)) {
                receivedActionStatic.when(() -> ProxyRequestReceivedAction.continueWith(cleanRequest, annotations))
                                    .thenReturn(mock(ProxyRequestReceivedAction.class));

                highlighter.handleRequestReceived(interceptedRequest);
            }

            ArgumentCaptor<String> note = ArgumentCaptor.forClass(String.class);
            verify(annotations).withNotes(note.capture());

            String marker = note.getValue().substring(0, note.getValue().indexOf(' '));
            assertNotEquals("⚪", marker, color + " fell through to the neutral marker");
            assertFalse(markersSeen.contains(marker), color + " reuses the marker " + marker);
            markersSeen.add(marker);
        }

        assertEquals(colors.size(), markersSeen.size());
    }

    @Test
    void leavesUntaggedRequestsCompletelyAloneAtReceiveStage() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);

        ProxyRequestReceivedAction expectedAction = mock(ProxyRequestReceivedAction.class);
        try (MockedStatic<ProxyRequestReceivedAction> receivedActionStatic = mockStatic(ProxyRequestReceivedAction.class)) {
            receivedActionStatic.when(() -> ProxyRequestReceivedAction.continueWith(interceptedRequest))
                                .thenReturn(expectedAction);

            assertSame(expectedAction, highlighter.handleRequestReceived(interceptedRequest));
        }

        verify(interceptedRequest, never()).withRemovedHeader(anyString());
        verify(interceptedRequest, never()).annotations();
    }

    @Test
    void stripsHeaderFromNonProxyToolsAsWell() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        HttpRequestToBeSent requestToBeSent = mock(HttpRequestToBeSent.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        stubHeaders(requestToBeSent, "red", null);
        when(requestToBeSent.withRemovedHeader(COLOR_HEADER)).thenReturn(cleanRequest);

        RequestToBeSentAction expectedAction = mock(RequestToBeSentAction.class);
        try (MockedStatic<RequestToBeSentAction> actionStatic = mockStatic(RequestToBeSentAction.class)) {
            actionStatic.when(() -> RequestToBeSentAction.continueWith(cleanRequest)).thenReturn(expectedAction);

            assertSame(expectedAction, highlighter.handleHttpRequestToBeSent(requestToBeSent));
        }
    }

    @Test
    void doesNotRewriteToolTrafficThatHasNoContainerHeader() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        HttpRequestToBeSent requestToBeSent = mock(HttpRequestToBeSent.class);

        RequestToBeSentAction expectedAction = mock(RequestToBeSentAction.class);
        try (MockedStatic<RequestToBeSentAction> actionStatic = mockStatic(RequestToBeSentAction.class)) {
            actionStatic.when(() -> RequestToBeSentAction.continueWith(requestToBeSent)).thenReturn(expectedAction);

            assertSame(expectedAction, highlighter.handleHttpRequestToBeSent(requestToBeSent));
        }

        verify(requestToBeSent, never()).withRemovedHeader(anyString());
    }

    @Test
    void stripsBothHeadersBeforeTheRequestIsSent() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        Annotations annotations = selfAnnotations();

        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
        HttpRequest withoutColor = mock(HttpRequest.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        stubHeaders(interceptedRequest, "red", "Attacker");
        when(interceptedRequest.annotations()).thenReturn(annotations);
        when(interceptedRequest.withRemovedHeader(COLOR_HEADER)).thenReturn(withoutColor);
        when(withoutColor.withRemovedHeader(NAME_HEADER)).thenReturn(cleanRequest);

        ProxyRequestToBeSentAction expectedAction = mock(ProxyRequestToBeSentAction.class);
        try (MockedStatic<ProxyRequestToBeSentAction> toBeSentActionStatic = mockStatic(ProxyRequestToBeSentAction.class)) {
            toBeSentActionStatic.when(() -> ProxyRequestToBeSentAction.continueWith(cleanRequest, annotations))
                                .thenReturn(expectedAction);

            assertSame(expectedAction, highlighter.handleRequestToBeSent(interceptedRequest));
        }

        verify(interceptedRequest).withRemovedHeader(COLOR_HEADER);
        verify(withoutColor).withRemovedHeader(NAME_HEADER);
    }

    @Test
    void stripsTheNameHeaderEvenWhenTheColourHeaderIsAbsent() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        Annotations annotations = selfAnnotations();

        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        stubHeaders(interceptedRequest, null, "Attacker");
        when(interceptedRequest.annotations()).thenReturn(annotations);
        when(interceptedRequest.withRemovedHeader(NAME_HEADER)).thenReturn(cleanRequest);

        ProxyRequestToBeSentAction expectedAction = mock(ProxyRequestToBeSentAction.class);
        try (MockedStatic<ProxyRequestToBeSentAction> toBeSentActionStatic = mockStatic(ProxyRequestToBeSentAction.class)) {
            toBeSentActionStatic.when(() -> ProxyRequestToBeSentAction.continueWith(cleanRequest, annotations))
                                .thenReturn(expectedAction);

            assertSame(expectedAction, highlighter.handleRequestToBeSent(interceptedRequest));
        }

        verify(annotations, never()).withHighlightColor(any());
    }

    /**
     * The safety net for Burp's own "Send to Repeater": that copies the original request, headers
     * and all, so the tab shows them. They must still never reach the wire when it is sent.
     */
    @Test
    void stripsBothHeadersWhenRepeaterSendsATabThatStillCarriesThem() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        HttpRequestToBeSent requestToBeSent = mock(HttpRequestToBeSent.class);
        HttpRequest withoutColor = mock(HttpRequest.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        stubHeaders(requestToBeSent, "red", "Attacker");
        when(requestToBeSent.withRemovedHeader(COLOR_HEADER)).thenReturn(withoutColor);
        when(withoutColor.withRemovedHeader(NAME_HEADER)).thenReturn(cleanRequest);

        RequestToBeSentAction expectedAction = mock(RequestToBeSentAction.class);
        try (MockedStatic<RequestToBeSentAction> actionStatic = mockStatic(RequestToBeSentAction.class)) {
            actionStatic.when(() -> RequestToBeSentAction.continueWith(cleanRequest)).thenReturn(expectedAction);

            assertSame(expectedAction, highlighter.handleHttpRequestToBeSent(requestToBeSent));
        }

        verify(requestToBeSent).withRemovedHeader(COLOR_HEADER);
        verify(withoutColor).withRemovedHeader(NAME_HEADER);
    }

    @Test
    void stripsTheNameHeaderFromNonProxyToolsAsWell() {
        ContainerHighlighter highlighter = new ContainerHighlighter();

        HttpRequestToBeSent requestToBeSent = mock(HttpRequestToBeSent.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        stubHeaders(requestToBeSent, null, "Attacker");
        when(requestToBeSent.withRemovedHeader(NAME_HEADER)).thenReturn(cleanRequest);

        RequestToBeSentAction expectedAction = mock(RequestToBeSentAction.class);
        try (MockedStatic<RequestToBeSentAction> actionStatic = mockStatic(RequestToBeSentAction.class)) {
            actionStatic.when(() -> RequestToBeSentAction.continueWith(cleanRequest)).thenReturn(expectedAction);

            assertSame(expectedAction, highlighter.handleHttpRequestToBeSent(requestToBeSent));
        }
    }

    @Test
    void showsItsReleaseVersionInBurp() {
        // PhoenixBox asks the user to confirm the JAR version before sending container names,
        // so the version has to be visible in Burp itself: in the Extensions list and the output.
        Logging logging = mock(Logging.class);
        MontoyaApi api = apiWith(logging);
        new ContainerHighlighter().initialize(api);

        String version = ContainerHighlighter.VERSION;
        assertTrue(version.matches("\\d+\\.\\d+\\.\\d+"), "version comes from the build, got: " + version);
        verify(api.extension()).setName("PhoenixBox Highlighter v" + version);
        verify(logging).logToOutput("PhoenixBox Highlighter v" + version + " loaded");
    }

    @Test
    void reportsEachUnrecognizedColorValueOnlyOnce() {
        Logging logging = mock(Logging.class);
        ContainerHighlighter highlighter = new ContainerHighlighter();
        highlighter.initialize(apiWith(logging));

        Annotations annotations = selfAnnotations();
        InterceptedRequest interceptedRequest = mock(InterceptedRequest.class);
        HttpRequest cleanRequest = mock(HttpRequest.class);
        stubHeaders(interceptedRequest, "Chartreuse", null);
        when(interceptedRequest.annotations()).thenReturn(annotations);
        when(interceptedRequest.withRemovedHeader(COLOR_HEADER)).thenReturn(cleanRequest);

        try (MockedStatic<ProxyRequestReceivedAction> receivedActionStatic = mockStatic(ProxyRequestReceivedAction.class)) {
            receivedActionStatic.when(() -> ProxyRequestReceivedAction.continueWith(cleanRequest, annotations))
                                .thenReturn(mock(ProxyRequestReceivedAction.class));

            highlighter.handleRequestReceived(interceptedRequest);
            highlighter.handleRequestReceived(interceptedRequest);
        }

        ArgumentCaptor<String> message = ArgumentCaptor.forClass(String.class);
        verify(logging, times(1)).logToError(message.capture());
        assertTrue(message.getValue().contains("chartreuse"), message.getValue());
    }

    @Test
    void namesRepeaterTabsWithSequenceNumberAndContainerColor() {
        Repeater repeater = mock(Repeater.class);
        ContainerHighlighter highlighter = new ContainerHighlighter();
        highlighter.initialize(apiWith(mock(Logging.class), repeater));

        HttpRequest cleanRed = mock(HttpRequest.class);
        HttpRequest cleanBlue = mock(HttpRequest.class);

        clickMenuItem(highlighter, contextMenuEventFor(taggedRequest(" Red ", cleanRed)));
        clickMenuItem(highlighter, contextMenuEventFor(taggedRequest("blue", cleanBlue)));

        verify(repeater).sendToRepeater(cleanRed, "1 red");
        verify(repeater).sendToRepeater(cleanBlue, "2 blue");
    }

    @Test
    void sendsTheStrippedRequestToRepeaterSoTheEditorMatchesTheWire() {
        Repeater repeater = mock(Repeater.class);
        ContainerHighlighter highlighter = new ContainerHighlighter();
        highlighter.initialize(apiWith(mock(Logging.class), repeater));

        HttpRequest cleanRequest = mock(HttpRequest.class);
        HttpRequest tagged = taggedRequest("red", cleanRequest);

        clickMenuItem(highlighter, contextMenuEventFor(tagged));

        verify(tagged).withRemovedHeader(COLOR_HEADER);
        verify(repeater, never()).sendToRepeater(same(tagged), anyString());
    }

    @Test
    void namesRepeaterTabsWithTheDecodedContainerName() {
        for (String[] vector : CONTAINER_NAME_VECTORS) {
            String expectedName = vector[0];
            String headerValue = vector[1];

            Repeater repeater = mock(Repeater.class);
            ContainerHighlighter highlighter = new ContainerHighlighter();
            highlighter.initialize(apiWith(mock(Logging.class), repeater));

            HttpRequest cleanRequest = mock(HttpRequest.class);
            clickMenuItem(highlighter,
                    contextMenuEventFor(taggedRequest("red", headerValue, cleanRequest)));

            verify(repeater).sendToRepeater(cleanRequest, "1 " + expectedName);
        }
    }

    @Test
    void fallsBackToTheColourWhenTheNameCannotBeDecoded() {
        Repeater repeater = mock(Repeater.class);
        ContainerHighlighter highlighter = new ContainerHighlighter();
        highlighter.initialize(apiWith(mock(Logging.class), repeater));

        HttpRequest cleanRequest = mock(HttpRequest.class);
        // A truncated escape sequence: URLDecoder throws on this.
        clickMenuItem(highlighter,
                contextMenuEventFor(taggedRequest("red", "%E0%A4%A", cleanRequest)));

        verify(repeater).sendToRepeater(cleanRequest, "1 red");
    }

    @Test
    void keepsControlCharactersOutOfRepeaterTabNames() {
        Repeater repeater = mock(Repeater.class);
        ContainerHighlighter highlighter = new ContainerHighlighter();
        highlighter.initialize(apiWith(mock(Logging.class), repeater));

        HttpRequest cleanRequest = mock(HttpRequest.class);
        clickMenuItem(highlighter,
                contextMenuEventFor(taggedRequest("red", "a%0D%0Ab", cleanRequest)));

        verify(repeater).sendToRepeater(cleanRequest, "1 ab");
    }

    @Test
    void namesRepeaterTabsFromTheStoredNoteWhenHeadersAreAlreadyGone() {
        Repeater repeater = mock(Repeater.class);
        ContainerHighlighter highlighter = new ContainerHighlighter();
        highlighter.initialize(apiWith(mock(Logging.class), repeater));

        // A request as it looks in HTTP history: both headers stripped, but our note survives.
        HttpRequest request = mock(HttpRequest.class);

        clickMenuItem(highlighter, contextMenuEventFor(notedRequestResponse(request, "🟢 Admin Account")));

        verify(repeater).sendToRepeater(request, "1 Admin Account");
    }

    /**
     * An editor can be focused while carrying no annotations of its own. Acting on the table
     * selection instead keeps the menu item from silently doing nothing.
     */
    @Test
    void fallsBackToTheTableSelectionWhenTheFocusedEditorIsNotTagged() {
        Repeater repeater = mock(Repeater.class);
        ContainerHighlighter highlighter = new ContainerHighlighter();
        highlighter.initialize(apiWith(mock(Logging.class), repeater));

        HttpRequestResponse untagged = mock(HttpRequestResponse.class);
        when(untagged.request()).thenReturn(mock(HttpRequest.class));

        HttpRequest request = mock(HttpRequest.class);
        HttpRequestResponse selected = notedRequestResponse(request, "🔵 Recon");

        MessageEditorHttpRequestResponse editor = mock(MessageEditorHttpRequestResponse.class);
        when(editor.requestResponse()).thenReturn(untagged);

        ContextMenuEvent event = mock(ContextMenuEvent.class);
        when(event.messageEditorRequestResponse()).thenReturn(Optional.of(editor));
        when(event.selectedRequestResponses()).thenReturn(List.of(selected));

        clickMenuItem(highlighter, event);

        verify(repeater).sendToRepeater(request, "1 Recon");
    }

    @Test
    void ignoresNotesThatAreNotOurs() {
        ContainerHighlighter highlighter = new ContainerHighlighter();
        highlighter.initialize(apiWith(mock(Logging.class), mock(Repeater.class)));

        HttpRequest request = mock(HttpRequest.class);

        // A note the user wrote themselves must not summon our menu item.
        ContextMenuEvent event = contextMenuEventFor(notedRequestResponse(request, "look at this later"));
        assertTrue(highlighter.provideMenuItems(event).isEmpty());
    }

    @Test
    void offersNoMenuItemForRequestsWithoutTheContainerHeader() {
        ContainerHighlighter highlighter = new ContainerHighlighter();
        highlighter.initialize(apiWith(mock(Logging.class), mock(Repeater.class)));

        HttpRequest request = mock(HttpRequest.class);

        assertTrue(highlighter.provideMenuItems(contextMenuEventFor(request)).isEmpty());
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

    private static HttpRequest taggedRequest(String colorValue, HttpRequest cleanRequest) {
        return taggedRequest(colorValue, null, cleanRequest);
    }

    private static HttpRequest taggedRequest(String colorValue, String nameValue, HttpRequest cleanRequest) {
        HttpRequest request = mock(HttpRequest.class);
        stubHeaders(request, colorValue, nameValue);
        when(request.withRemovedHeader(COLOR_HEADER)).thenReturn(cleanRequest);
        when(request.withRemovedHeader(NAME_HEADER)).thenReturn(cleanRequest);
        // Stripping chains one header removal off the result of the other.
        when(cleanRequest.withRemovedHeader(NAME_HEADER)).thenReturn(cleanRequest);
        return request;
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

    private static ContextMenuEvent contextMenuEventFor(HttpRequest request) {
        HttpRequestResponse requestResponse = mock(HttpRequestResponse.class);
        when(requestResponse.request()).thenReturn(request);
        return contextMenuEventFor(requestResponse);
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
