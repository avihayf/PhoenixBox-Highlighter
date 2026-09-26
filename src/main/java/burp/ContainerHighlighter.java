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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static java.util.Collections.emptyList;

/**
 * Colors proxy traffic by the PhoenixBox container it came from, in one of two modes.
 *
 * <ul>
 *   <li><b>Paired</b> with PhoenixBox: each marked container has its own proxy listener (see
 *       {@link SyncService}), and a request's container is known from the listener it arrived
 *       on. It is coloured and noted with the container's name. PhoenixBox sends no headers in
 *       this mode, so none are read or stripped.
 *   <li><b>Not paired</b> (legacy): PhoenixBox marks a container's requests with an
 *       {@code x-mac-container-color} header, as it does for the old v1.x Highlighter. The request
 *       is coloured, with no note, and the header is stripped at two independent points so it never
 *       reaches the target: the Proxy handler for browser traffic, and the HTTP handler for every
 *       tool.
 * </ul>
 */
public class ContainerHighlighter implements BurpExtension, ProxyRequestHandler, HttpHandler, ContextMenuItemsProvider {

    /** The release version, stamped in by the build and shown in Burp. */
    static final String VERSION = readVersion();

    private static final String HEADER_NAME = "x-mac-container-color";
    private static final String NAME_HEADER_NAME = "x-mac-container-name";

    /** Stripped in legacy mode. The name is never sent by PhoenixBox 3.1, but removing it costs nothing. */
    private static final List<String> MANAGED_HEADERS = List.of(HEADER_NAME, NAME_HEADER_NAME);

    /**
     * The colour values PhoenixBox emits. It normalises Firefox's container palette before
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

    /** How much of an unrecognised value we echo to the log; the header is attacker-influenced. */
    private static final int MAX_LOGGED_COLOR_LENGTH = 64;

    private final Set<String> reportedUnknownColors = ConcurrentHashMap.newKeySet();

    /**
     * Burp numbers Repeater tabs itself, but supplying a tab name replaces that number rather than
     * appending to it, and the next index cannot be read back through the API. So we keep our own
     * sequence to reproduce the numbering alongside the container name.
     */
    private final AtomicInteger repeaterTabNumber = new AtomicInteger();

    private volatile Logging logging;
    private volatile Repeater repeater;

    /** False only in tests, which must not open sockets or touch Burp's settings. */
    private final boolean connectToPhoenixBox;

    /** Which container each of our listeners belongs to. Empty until PhoenixBox first syncs. */
    private final ContainerRegistry registry = new ContainerRegistry();

    /** Replaced with the project-backed set once Burp hands us persistence. */
    private volatile KnownNames knownNames = new KnownNames(null);

    /** Whether a paired PhoenixBox is driving highlighting. Read for every proxied request. */
    private volatile BooleanSupplier paired = () -> false;

    private volatile ListenerManager listenerManager;
    private volatile ControlServer controlServer;
    private volatile ScheduledExecutorService leaseTimer;
    private volatile HighlighterTab tab;

    public ContainerHighlighter() {
        this(true);
    }

    ContainerHighlighter(boolean connectToPhoenixBox) {
        this.connectToPhoenixBox = connectToPhoenixBox;
    }

    ContainerRegistry registry() {
        return registry;
    }

    KnownNames knownNames() {
        return knownNames;
    }

    void setPairedCheck(BooleanSupplier paired) {
        this.paired = paired;
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.logging = api.logging();
        this.repeater = api.repeater();

        String title = "PhoenixBox Highlighter v" + VERSION;
        api.extension().setName(title);
        api.proxy().registerRequestHandler(this);
        api.http().registerHttpHandler(this);
        api.userInterface().registerContextMenuItemsProvider(this);
        api.extension().registerUnloadingHandler(this::shutdown);

        try {
            if (connectToPhoenixBox) {
                startListenerService(api);
            }
        } catch (RuntimeException e) {
            // Pairing is unavailable, but legacy colouring and stripping keep working.
            api.logging().logToError(title + ": could not start the PhoenixBox connection: " + e);
        }

        api.logging().logToOutput(title + " loaded");
    }

    /** The token behind the manual pairing string, for when PhoenixBox cannot discover Burp. */
    private static final String TOKEN_KEY = "pairingToken";
    /** The PhoenixBox profiles approved in Burp, with their tokens. */
    private static final String CLIENTS_KEY = "pairedClients";
    /** Where early 2.0.0 builds remembered the control port; now cleared on load. */
    private static final String LEGACY_CONTROL_PORT_KEY = "controlPort";

    private volatile String controlHost = ListenerAddress.LOOPBACK;
    private volatile int controlPort = -1;

    private void startListenerService(MontoyaApi api) {
        ListenerManager.Store projectStore = new ListenerManager.Store() {
            @Override
            public String get(String key) {
                return api.persistence().extensionData().getString(key);
            }

            @Override
            public void set(String key, String value) {
                api.persistence().extensionData().setString(key, value);
            }
        };
        ListenerManager.ProjectOptions options = new ListenerManager.ProjectOptions() {
            @Override
            public String exportListeners() {
                return api.burpSuite().exportProjectOptionsAsJson(ListenerConfig.PATH);
            }

            @Override
            public void importListeners(String json) {
                api.burpSuite().importProjectOptionsFromJson(json);
            }
        };

        knownNames = new KnownNames(projectStore);
        ListenerManager manager = new ListenerManager(options, projectStore);
        manager.removeLeftovers();
        listenerManager = manager;

        if (api.persistence().preferences().getString(TOKEN_KEY) == null) {
            api.persistence().preferences().setString(TOKEN_KEY, Pairing.newToken());
        }
        api.persistence().preferences().deleteInteger(LEGACY_CONTROL_PORT_KEY);

        PairingService pairing = new PairingService(new PairingService.Store() {
            @Override
            public String get() {
                return api.persistence().preferences().getString(CLIENTS_KEY);
            }

            @Override
            public void set(String json) {
                api.persistence().preferences().setString(CLIENTS_KEY, json);
            }
        }, api.persistence().preferences().getString(TOKEN_KEY), System::currentTimeMillis);

        controlHost = Pairing.bindHost(manager.userListeners());
        SyncService sync = new SyncService(manager, registry, knownNames, new AddressProbe.Sockets(),
                new ListenerAddress(controlHost, ControlServer.DEFAULT_PORT),
                System::currentTimeMillis);
        paired = sync::isPaired;

        ControlServer server = new ControlServer(new ControlServer.Handler(pairing, sync),
                api.logging()::logToError);
        try {
            controlPort = server.start(controlHost);
            sync.setControl(new ListenerAddress(controlHost, controlPort));
            controlServer = server;
        } catch (IOException e) {
            api.logging().logToError("PhoenixBox Highlighter: no free control port between "
                    + ControlServer.DEFAULT_PORT + " and " + ControlServer.LAST_PORT + " on " + controlHost + ": " + e);
        }

        ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "phoenixbox-lease");
            thread.setDaemon(true);
            return thread;
        });
        timer.scheduleWithFixedDelay(() -> {
            try {
                sync.expireIfIdle();
            } catch (RuntimeException e) {
                api.logging().logToError("PhoenixBox Highlighter: closing idle listeners failed: " + e);
            }
        }, 10, 10, TimeUnit.SECONDS);
        leaseTimer = timer;

        HighlighterTab panel = new HighlighterTab(
                () -> controlPort < 0
                        ? "(control server not running)"
                        : Pairing.pairingString(controlHost, controlPort, pairing.manualToken()),
                () -> controlPort < 0 ? "control server not running" : "listening for PhoenixBox on "
                        + (controlHost.contains(":") ? "[" + controlHost + "]" : controlHost) + ":" + controlPort,
                () -> {
                    String token = Pairing.newToken();
                    api.persistence().preferences().setString(TOKEN_KEY, token);
                    pairing.revokeAll(token);
                },
                // Off the UI thread: releasing changes Burp's listeners, which Burp does on it.
                () -> timer.execute(() -> {
                    try {
                        sync.releaseNow();
                    } catch (RuntimeException e) {
                        api.logging().logToError("PhoenixBox Highlighter: releasing after a revoke failed: " + e);
                    }
                }),
                sync, pairing, api.userInterface().swingUtils().suiteFrame());
        pairing.setPrompt(panel::promptForPairing);
        api.userInterface().applyThemeToComponent(panel);
        api.userInterface().registerSuiteTab("PhoenixBox", panel);
        tab = panel;
    }

    /** Closes our listeners before anything else, so an unload never leaves them behind. */
    private void shutdown() {
        ScheduledExecutorService timer = leaseTimer;
        if (timer != null) {
            timer.shutdownNow();
        }
        HighlighterTab panel = tab;
        if (panel != null) {
            panel.stop();
        }
        ListenerManager manager = listenerManager;
        if (manager != null) {
            try {
                manager.removeAll();
            } catch (RuntimeException e) {
                Logging log = logging;
                if (log != null) {
                    log.logToError("PhoenixBox Highlighter: could not remove container listeners: " + e);
                }
            }
        }
        registry.clear();
        paired = () -> false;
        ControlServer server = controlServer;
        if (server != null) {
            server.stop();
        }
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
     * exposes a tab name and nothing else.
     *
     * <p>The label comes from the note written for traffic on a container's listener, so this works
     * from HTTP history as well as Proxy &gt; Intercept.
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

        target.sendToRepeater(requestResponse.request(), repeaterTabNumber.incrementAndGet() + " " + label);
    }

    /** The PhoenixBox requests a context-menu invocation applies to. */
    private List<HttpRequestResponse> taggedRequestResponses(
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

    private List<HttpRequestResponse> tagged(List<HttpRequestResponse> candidates) {
        List<HttpRequestResponse> requestResponses = new ArrayList<>(candidates);
        requestResponses.removeIf(requestResponse -> containerLabel(requestResponse) == null);
        return requestResponses;
    }

    /**
     * The container a request-response belongs to, from the note written for traffic on its
     * listener, or {@code null} when it is not one of ours. A note counts when it is exactly a
     * container name this extension has written.
     */
    private String containerLabel(HttpRequestResponse requestResponse) {
        if (requestResponse == null) {
            return null;
        }

        Annotations annotations = requestResponse.annotations();
        if (annotations == null || !annotations.hasNotes() || annotations.notes() == null) {
            return null;
        }

        String note = annotations.notes().trim();
        return knownNames.contains(note) ? note : null;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        // Everything happens here, at the first stage the Proxy sees, because Burp's HTTP history
        // shows the *received* request.
        ContainerRegistry.Container container = registry.lookup(interceptedRequest.listenerInterface());

        if (container != null) {
            // Arrived on a container's listener: colour it and name it, and forward it exactly as
            // the browser sent it.
            return ProxyRequestReceivedAction.continueWith(interceptedRequest,
                    annotateForListener(container, interceptedRequest.annotations()));
        }

        if (paired.getAsBoolean()) {
            // A paired PhoenixBox sends no headers, so there is nothing to read or strip.
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }

        // Legacy: colour from the header, then strip it so it never appears in history, in the
        // Intercept editor, or on the wire.
        HttpRequest cleanRequest = withManagedHeadersRemoved(interceptedRequest);
        if (cleanRequest == null) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
        return ProxyRequestReceivedAction.continueWith(cleanRequest,
                colourFromHeader(interceptedRequest, interceptedRequest.annotations()));
    }

    /**
     * Legacy backstop for proxy traffic: {@link #handleRequestReceived} has already stripped the
     * header, so this normally finds nothing. It only bites if a request somehow reaches the send
     * stage without having passed through the receive stage.
     */
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        if (paired.getAsBoolean()) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }

        HttpRequest cleanRequest = withManagedHeadersRemoved(interceptedRequest);
        if (cleanRequest == null) {
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        }
        return ProxyRequestToBeSentAction.continueWith(cleanRequest,
                colourFromHeader(interceptedRequest, interceptedRequest.annotations()));
    }

    /**
     * Legacy backstop for every tool, for requests that never passed through the Proxy handler while
     * this extension was loaded, so the header cannot escape to the target from any tool.
     */
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (paired.getAsBoolean()) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        HttpRequest cleanRequest = withManagedHeadersRemoved(requestToBeSent);
        return RequestToBeSentAction.continueWith(cleanRequest == null ? requestToBeSent : cleanRequest);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /** Legacy mode: the highlight alone carries the container, with no note. */
    private Annotations colourFromHeader(HttpRequest request, Annotations annotations) {
        String colorValue = containerColorValue(request);
        HighlightColor highlight = colorValue == null ? null : COLOR_MAP.get(colorValue);

        if (highlight != null) {
            return annotations.withHighlightColor(highlight);
        }
        if (colorValue != null) {
            reportUnrecognizedColor(colorValue);
        }
        return annotations;
    }

    /** The note is the bare container name; the highlight alone carries the colour. */
    private static Annotations annotateForListener(ContainerRegistry.Container container, Annotations annotations) {
        HighlightColor highlight = container.color() == null ? null : COLOR_MAP.get(container.color());
        if (highlight != null) {
            annotations = annotations.withHighlightColor(highlight);
        }
        // Never clobber a note the user already wrote.
        if (!annotations.hasNotes()) {
            annotations = annotations.withNotes(container.name());
        }
        return annotations;
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

    private void reportUnrecognizedColor(String colorValue) {
        Logging log = logging;

        if (log == null || colorValue.isEmpty() || reportedUnknownColors.size() >= MAX_REPORTED_UNKNOWN_COLORS) {
            return;
        }

        if (reportedUnknownColors.add(colorValue)) {
            String shown = colorValue.length() > MAX_LOGGED_COLOR_LENGTH
                    ? colorValue.substring(0, MAX_LOGGED_COLOR_LENGTH) + "…"
                    : colorValue;
            log.logToError("PhoenixBox Highlighter: no highlight for " + HEADER_NAME + " value '"
                    + shown + "'. Supported values: " + SUPPORTED_VALUES);
        }
    }
}
