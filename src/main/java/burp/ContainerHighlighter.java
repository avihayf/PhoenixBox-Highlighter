/**
 * @author 0xR3DB0MB
 */
package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.repeater.Repeater;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import static java.util.Collections.emptyList;

/**
 * Colors proxy traffic according to the {@code x-mac-container-color} header injected by the
 * PhoenixBox Firefox extension.
 *
 * <p>The header exists purely to drive highlighting inside Burp and must never reach the target,
 * so it is removed on the way out at two independent points: the Proxy handler strips it from
 * browser traffic, and the HTTP handler strips it from every tool as a backstop.
 */
public class ContainerHighlighter implements BurpExtension, ProxyRequestHandler, HttpHandler, ContextMenuItemsProvider {

    /**
     * The release version, stamped in by the build. PhoenixBox withholds the container-name header
     * until the user confirms a new enough JAR, so the version is shown where they can check it.
     */
    static final String VERSION = readVersion();

    private static final String HEADER_NAME = "x-mac-container-color";
    private static final String NAME_HEADER_NAME = "x-mac-container-name";

    /** Everything PhoenixBox injects, and therefore everything we have to take back out. */
    private static final List<String> MANAGED_HEADERS = List.of(HEADER_NAME, NAME_HEADER_NAME);

    /** Mirrors the cap PhoenixBox applies before encoding; re-applied here since the header is untrusted. */
    private static final int MAX_CONTAINER_NAME_LENGTH = 64;

    private static final Pattern CONTROL_CHARACTERS = Pattern.compile("\\p{Cntrl}");

    /**
     * The marker prefixed to the note we write for container attribution. It shows in Burp's Notes
     * column as a colour cue, tells the "Send to Repeater (PhoenixBox)" action which requests are
     * ours, and carries the tab label after the headers themselves have been stripped.
     *
     * <p>Emoji has no cyan or pink circle — the round set stops at red/orange/yellow/green/blue/
     * purple/brown/black/white — so those two use the closest correctly-hued glyph instead. Every
     * marker here predates Unicode 15, which keeps them renderable on older Java/OS combinations.
     */
    private static final Map<String, String> COLOR_MARKERS = Map.of(
            "red", "🔴",
            "orange", "🟠",
            "yellow", "🟡",
            "green", "🟢",
            "blue", "🔵",
            "cyan", "💠",
            "pink", "💗",
            "magenta", "🟣"
    );

    /** Used when a request is tagged with a colour we do not recognise. */
    private static final String UNKNOWN_COLOR_MARKER = "⚪";


    /** Every marker we might have written, for recognising our own notes later. */
    private static final Set<String> ALL_MARKERS = markerSet();

    private static Set<String> markerSet() {
        Set<String> markers = new HashSet<>(COLOR_MARKERS.values());
        markers.add(UNKNOWN_COLOR_MARKER);
        return Set.copyOf(markers);
    }

    /**
     * The values PhoenixBox emits. It already normalises Firefox's container palette before
     * sending, mapping turquoise to cyan and purple to magenta.
     */
    private static final Map<String, HighlightColor> COLOR_MAP = Map.of(
            "blue", HighlightColor.BLUE,
            "cyan", HighlightColor.CYAN,
            "green", HighlightColor.GREEN,
            "yellow", HighlightColor.YELLOW,
            "orange", HighlightColor.ORANGE,
            "red", HighlightColor.RED,
            "pink", HighlightColor.PINK,
            "magenta", HighlightColor.MAGENTA
    );

    private static final String SUPPORTED_VALUES = String.join(", ", new TreeSet<>(COLOR_MAP.keySet()));

    /** Ceiling on distinct unrecognised values we report, so a noisy source cannot grow this set. */
    private static final int MAX_REPORTED_UNKNOWN_COLORS = 32;

    private final Set<String> reportedUnknownColors = ConcurrentHashMap.newKeySet();

    /**
     * Burp numbers Repeater tabs itself, but supplying a tab name replaces that number rather than
     * appending to it, and the next index cannot be read back through the API. So we keep our own
     * sequence to reproduce the numbering alongside the container color.
     */
    private final AtomicInteger repeaterTabNumber = new AtomicInteger();

    private volatile Logging logging;
    private volatile Repeater repeater;

    @Override
    public void initialize(MontoyaApi api) {
        this.logging = api.logging();
        this.repeater = api.repeater();

        String title = "PhoenixBox Highlighter v" + VERSION;
        api.extension().setName(title);
        api.proxy().registerRequestHandler(this);
        api.http().registerHttpHandler(this);
        api.userInterface().registerContextMenuItemsProvider(this);

        api.logging().logToOutput(title + " loaded");
    }

    private static String readVersion() {
        try (InputStream in = ContainerHighlighter.class.getResourceAsStream("/phoenixbox-highlighter.properties")) {
            if (in != null) {
                Properties properties = new Properties();
                properties.load(in);
                String version = properties.getProperty("version", "").trim();

                // An unexpanded placeholder means the resource was not processed by the build.
                if (!version.isEmpty() && !version.startsWith("$")) {
                    return version;
                }
            }
        } catch (IOException ignored) {
            // Fall through: an unknown version must never stop the extension loading.
        }

        return "unknown";
    }

    /**
     * Adds a "Send to Repeater" entry that names the tab {@code <number> <container>} so container
     * attribution survives into Repeater, where tabs cannot be colored — Burp's Repeater API
     * exposes a tab name and nothing else. The label prefers the container's name and falls back
     * to its color.
     *
     * <p>The label comes from the note we set at the receive stage, so this works from HTTP history
     * as well as Proxy &gt; Intercept, even though the headers themselves have been stripped by then.
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> tagged = taggedRequestResponses(
                event.messageEditorRequestResponse().orElse(null), event.selectedRequestResponses());

        if (tagged.isEmpty()) {
            return emptyList();
        }

        JMenuItem item = new JMenuItem("Send to Repeater (PhoenixBox)");
        item.addActionListener(e -> tagged.forEach(this::sendToRepeaterWithContainerName));

        return List.of(item);
    }

    private void sendToRepeaterWithContainerName(HttpRequestResponse requestResponse) {
        Repeater target = repeater;
        String label = containerLabel(requestResponse);

        if (target == null || label == null) {
            return;
        }

        String tabName = repeaterTabNumber.incrementAndGet() + " " + label;

        // Send the stripped request: the tab name carries the attribution, and the headers should
        // never be on a request Burp sends anyway.
        HttpRequest request = requestResponse.request();
        HttpRequest cleanRequest = withManagedHeadersRemoved(request);
        target.sendToRepeater(cleanRequest == null ? request : cleanRequest, tabName);
    }

    /** The PhoenixBox requests a context-menu invocation applies to. */
    private static List<HttpRequestResponse> taggedRequestResponses(
            MessageEditorHttpRequestResponse editor, List<HttpRequestResponse> selected) {
        // Prefer whatever is open in an editor, but fall back to the table selection rather than
        // giving up: an editor can be focused while carrying no annotations of its own, and
        // returning nothing there would hide the menu item when the selected row does qualify.
        if (editor != null) {
            List<HttpRequestResponse> fromEditor = tagged(List.of(editor.requestResponse()));

            if (!fromEditor.isEmpty()) {
                return fromEditor;
            }
        }

        return selected == null ? new ArrayList<>() : tagged(selected);
    }

    private static List<HttpRequestResponse> tagged(List<HttpRequestResponse> candidates) {
        List<HttpRequestResponse> requestResponses = new ArrayList<>(candidates);
        requestResponses.removeIf(requestResponse -> containerLabel(requestResponse) == null);
        return requestResponses;
    }

    /**
     * The container label for a request-response, or {@code null} when it is not one of ours.
     *
     * <p>Reads the note we recorded at the receive stage first, since that is all that survives once
     * the headers are stripped, then falls back to the headers for a request captured before
     * stripping (e.g. one held in the Intercept editor of an older session).
     */
    private static String containerLabel(HttpRequestResponse requestResponse) {
        if (requestResponse == null) {
            return null;
        }

        Annotations annotations = requestResponse.annotations();

        if (annotations != null && annotations.hasNotes()) {
            String label = labelFromNote(annotations.notes());

            if (label != null) {
                return label;
            }
        }

        return containerLabelFromHeaders(requestResponse.request());
    }

    /**
     * The container label carried by one of our notes, or {@code null} for a note we did not write.
     */
    private static String labelFromNote(String note) {
        if (note == null) {
            return null;
        }

        for (String marker : ALL_MARKERS) {
            if (note.startsWith(marker)) {
                String label = note.substring(marker.length()).trim();

                if (!label.isEmpty()) {
                    return label;
                }
            }
        }

        return null;
    }

    /**
     * The container label read directly off the headers: the decoded name, or the colour when no
     * name was sent. {@code null} when the request carries neither.
     */
    private static String containerLabelFromHeaders(HttpRequest request) {
        if (request == null) {
            return null;
        }

        String name = containerNameValue(request);

        if (name != null) {
            return name;
        }

        String color = containerColorValue(request);

        return color == null || color.isEmpty() ? null : color;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        // Everything happens here, at the first stage the Proxy sees, because Burp's HTTP history
        // shows the *received* request. Colour it, record the container as a note so the attribution
        // survives, then strip both headers — so they never appear in history, in the Intercept
        // editor, or on the wire.
        HttpRequest cleanRequest = withManagedHeadersRemoved(interceptedRequest);

        if (cleanRequest == null) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        Annotations annotations = annotateForContainer(interceptedRequest, interceptedRequest.annotations());
        return ProxyRequestReceivedAction.continueWith(cleanRequest, annotations);
    }

    /**
     * Defensive backstop for proxy traffic: {@link #handleRequestReceived} has already stripped the
     * headers, so this normally finds nothing. It only bites if a request somehow reaches the send
     * stage without having passed through the receive stage.
     */
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        HttpRequest cleanRequest = withManagedHeadersRemoved(interceptedRequest);

        if (cleanRequest == null) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }

        Annotations annotations = annotateForContainer(interceptedRequest, interceptedRequest.annotations());
        return ProxyRequestToBeSentAction.continueWith(cleanRequest, annotations);
    }

    /**
     * Applies the highlight colour and records the container attribution as a note, so it outlives
     * the header strip and travels into HTTP history and the context menu.
     */
    private Annotations annotateForContainer(HttpRequest request, Annotations annotations) {
        String colorValue = containerColorValue(request);
        HighlightColor highlight = colorValue == null ? null : COLOR_MAP.get(colorValue);

        if (highlight != null) {
            annotations = annotations.withHighlightColor(highlight);
        } else if (colorValue != null) {
            reportUnrecognizedColor(colorValue);
        }

        // Prefer the container's own name and fall back to its colour, so a note is set even for an
        // older PhoenixBox that only sends the colour. Never clobber a note the user already wrote.
        String label = containerLabelFromHeaders(request);

        if (label != null && !annotations.hasNotes()) {
            annotations = annotations.withNotes(markerFor(colorValue) + " " + label);
        }

        return annotations;
    }

    private static String markerFor(String colorValue) {
        String marker = colorValue == null ? null : COLOR_MARKERS.get(colorValue);
        return marker == null ? UNKNOWN_COLOR_MARKER : marker;
    }

    /**
     * Backstop for requests that never passed through the Proxy handler while this extension was
     * loaded — a Repeater tab captured before the extension was enabled, for example — so the
     * header cannot escape to the target from any tool.
     */
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        HttpRequest cleanRequest = withManagedHeadersRemoved(requestToBeSent);

        if (cleanRequest == null) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        return RequestToBeSentAction.continueWith(cleanRequest);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private static String containerColorValue(HttpRequest request) {
        String value = headerValueIgnoringCase(request, HEADER_NAME);
        return value == null ? null : value.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Returns every PhoenixBox header stripped from the request, or {@code null} when it carried
     * none — letting callers forward the original instance untouched.
     *
     * <p>Works off the request's own header list and removes each header by the exact name it was
     * sent with, rather than relying on Burp matching our lower-case constant case-insensitively.
     */
    private static HttpRequest withManagedHeadersRemoved(HttpRequest request) {
        HttpRequest stripped = null;

        for (HttpHeader header : request.headers()) {
            String name = header == null ? null : header.name();

            if (isManagedHeader(name)) {
                stripped = (stripped == null ? request : stripped).withRemovedHeader(name);
            }
        }

        return stripped;
    }

    private static boolean isManagedHeader(String headerName) {
        return headerName != null
                && MANAGED_HEADERS.contains(headerName.trim().toLowerCase(Locale.ROOT));
    }

    /** Case-insensitive header lookup that does not depend on Burp's own matching rules. */
    private static String headerValueIgnoringCase(HttpRequest request, String headerName) {
        for (HttpHeader header : request.headers()) {
            String name = header == null ? null : header.name();

            if (name != null && name.trim().equalsIgnoreCase(headerName)) {
                return header.value();
            }
        }

        return null;
    }

    /**
     * Decodes the percent-encoded container name PhoenixBox sends.
     *
     * @return the decoded name, or {@code null} when it is absent, blank or unusable.
     */
    private static String containerNameValue(HttpRequest request) {
        String value = headerValueIgnoringCase(request, NAME_HEADER_NAME);

        if (value == null) {
            return null;
        }

        String trimmed = value.trim();

        if (trimmed.isEmpty()) {
            return null;
        }

        String decoded;

        try {
            // URLDecoder reads "+" as a space because it implements form encoding, but the sender
            // uses encodeURIComponent, which escapes a literal plus as "%2B" and never emits a bare
            // one. Escaping it first is what keeps a container named "C++" intact.
            decoded = URLDecoder.decode(trimmed.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // A malformed escape sequence. This runs on the proxy hot path, so fall back to the
            // colour rather than letting it propagate.
            return null;
        }

        // The value is attacker-influenced and ends up in a Repeater tab label, so drop control
        // characters and re-apply the sender's length cap rather than trusting either.
        String cleaned = CONTROL_CHARACTERS.matcher(decoded).replaceAll("").trim();

        if (cleaned.isEmpty()) {
            return null;
        }

        return cleaned.codePointCount(0, cleaned.length()) > MAX_CONTAINER_NAME_LENGTH
                ? cleaned.substring(0, cleaned.offsetByCodePoints(0, MAX_CONTAINER_NAME_LENGTH))
                : cleaned;
    }

    private void reportUnrecognizedColor(String colorValue) {
        Logging log = logging;

        if (log == null || colorValue.isEmpty() || reportedUnknownColors.size() >= MAX_REPORTED_UNKNOWN_COLORS) {
            return;
        }

        if (reportedUnknownColors.add(colorValue)) {
            log.logToError("PhoenixBox Highlighter: no highlight for " + HEADER_NAME + " value '"
                    + colorValue + "'. Supported values: " + SUPPORTED_VALUES);
        }
    }
}
