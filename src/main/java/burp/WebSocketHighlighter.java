package burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.MalformedRequestException;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction;
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyMessageHandler;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction;
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction;

import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/** Carries HTTP listener attribution into a WebSocket without adding anything to the wire. */
final class WebSocketHighlighter implements ProxyWebSocketCreationHandler, AutoCloseable {
    private record Attribution(HighlightColor color, String name) {
        boolean isKnown() {
            return color != null || name != null;
        }

        void annotate(Annotations annotations) {
            if (color != null) annotations.setHighlightColor(color);
            if (name != null && !annotations.hasNotes()) annotations.setNotes(name);
        }
    }

    private record Key(String host, int port, boolean secure, String path, String handshakeKey) {
        static Key from(HttpRequest request) {
            try {
                return parse(request);
            } catch (MalformedRequestException e) {
                // Malformed test traffic still needs the normal HTTP annotation/cleaning path.
                return null;
            }
        }

        private static Key parse(HttpRequest request) {
            if (!"GET".equalsIgnoreCase(request.method())) return null;
            List<HttpHeader> headers = request.headers();
            if (!hasToken(headers, "Upgrade", "websocket") || !hasToken(headers, "Connection", "upgrade")) {
                return null;
            }
            String key = null;
            for (HttpHeader header : headers) {
                if (header != null && "Sec-WebSocket-Key".equalsIgnoreCase(header.name())) {
                    // Duplicate keys do not identify one safe handshake.
                    if (key != null || header.value() == null) return null;
                    key = header.value().trim();
                }
            }
            HttpService service = request.httpService();
            String path = request.path();
            if (key == null || key.isEmpty() || service == null || service.host() == null || path == null) return null;
            // Temporary correlation state must not retain arbitrarily large attacker-controlled strings.
            if (key.length() > 128 || service.host().length() > 253 || path.length() > 8192) return null;
            return new Key(service.host().toLowerCase(Locale.ROOT), service.port(), service.secure(), path, key);
        }

        private static boolean hasToken(List<HttpHeader> headers, String name, String expected) {
            for (HttpHeader header : headers) {
                if (header == null || !name.equalsIgnoreCase(header.name()) || header.value() == null) continue;
                for (String token : header.value().split(",")) {
                    if (expected.equalsIgnoreCase(token.trim())) return true;
                }
            }
            return false;
        }
    }

    private static final class Pending {
        final int messageId;
        final Attribution attribution;
        final long created;
        Key key;

        Pending(int messageId, Key key, Attribution attribution, long created) {
            this.messageId = messageId;
            this.key = key;
            this.attribution = attribution;
            this.created = created;
        }
    }

    private static final class Candidates {
        final Set<Integer> ids = new HashSet<>();
        // Sticky while this key exists: removing one duplicate must not bless the other.
        boolean ambiguous;
    }

    private final LongSupplier clock;
    private final int capacity;
    private final long timeoutNanos;
    private final Map<Integer, Pending> pending = new HashMap<>();
    private final Map<Key, Candidates> candidates = new HashMap<>();
    private final Set<Connection> connections = new HashSet<>();
    // A fixed 1 MiB Bloom filter remembers keys even after pending records expire or are rejected.
    // Bits are never cleared while loaded: false positives only omit labels, never misattribute them.
    private static final int SEEN_BITS = 1 << 23;
    private final BitSet seenKeys = new BitSet(SEEN_BITS);
    private final MessageDigest fingerprint;
    private boolean closed;

    WebSocketHighlighter() {
        this(System::nanoTime, 4096, Duration.ofMinutes(5));
    }

    WebSocketHighlighter(LongSupplier clock, int capacity, Duration timeout) {
        if (capacity < 1 || timeout.isNegative() || timeout.isZero()) throw new IllegalArgumentException();
        this.clock = clock;
        this.capacity = capacity;
        this.timeoutNanos = timeout.toNanos();
        try {
            this.fingerprint = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Java's required SHA-256 digest is unavailable", e);
        }
    }

    /** Called before legacy attribution headers are stripped. Null attribution also detects collisions. */
    synchronized void rememberUpgrade(InterceptedRequest request, HighlightColor color, String name) {
        if (closed) return;
        prune();
        if (pending.containsKey(request.messageId())) return;
        Key key = Key.from(request);
        if (key == null) return;
        boolean seen = markSeen(key);
        Candidates existing = candidates.get(key);
        if (seen && existing != null) existing.ambiguous = true;
        if (pending.size() >= capacity) {
            return;
        }
        Pending entry = new Pending(request.messageId(), key, new Attribution(color, name), clock.getAsLong());
        pending.put(entry.messageId, entry);
        addCandidate(entry);
        if (seen) candidates.get(key).ambiguous = true;
    }

    /** Follow interception edits using Burp's HTTP message ID, preserving the received attribution. */
    synchronized void observeUpgradeToBeSent(InterceptedRequest request) {
        if (closed) return;
        prune();
        Pending entry = pending.get(request.messageId());
        Key key = Key.from(request);
        if (entry == null) {
            // Even an expired/rejected request can be edited onto a tracked request's key.
            if (key != null) {
                markSeen(key);
                Candidates group = candidates.get(key);
                if (group != null) group.ambiguous = true;
            }
            return;
        }
        if (entry.key.equals(key)) return;
        removeCandidate(entry);
        if (key == null) {
            pending.remove(entry.messageId);
        } else {
            entry.key = key;
            boolean seen = markSeen(key);
            addCandidate(entry);
            if (seen) candidates.get(key).ambiguous = true;
        }
    }

    /** Called only under our monitor, along with all other correlation state. */
    private boolean markSeen(Key key) {
        byte[] hash = fingerprint.digest(key.toString().getBytes(StandardCharsets.UTF_8));
        boolean seen = true;
        for (int i = 0; i < 16; i += 4) {
            int bit = (((hash[i] & 255) << 24) | ((hash[i + 1] & 255) << 16)
                    | ((hash[i + 2] & 255) << 8) | (hash[i + 3] & 255)) & (SEEN_BITS - 1);
            seen &= seenKeys.get(bit);
            seenKeys.set(bit);
        }
        return seen;
    }

    private void addCandidate(Pending entry) {
        Candidates group = candidates.computeIfAbsent(entry.key, ignored -> new Candidates());
        group.ids.add(entry.messageId);
        if (group.ids.size() > 1) group.ambiguous = true;
    }

    private void removeCandidate(Pending entry) {
        Candidates group = candidates.get(entry.key);
        group.ids.remove(entry.messageId);
        if (group.ids.isEmpty()) candidates.remove(entry.key);
    }

    private void prune() {
        long now = clock.getAsLong();
        Iterator<Pending> entries = pending.values().iterator();
        while (entries.hasNext()) {
            Pending entry = entries.next();
            if (now - entry.created >= timeoutNanos) {
                removeCandidate(entry);
                entries.remove();
            }
        }
    }

    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation creation) {
        Connection connection;
        synchronized (this) {
            if (closed) return;
            prune();
            Key key = Key.from(creation.upgradeRequest());
            Candidates group = candidates.get(key);
            if (group == null || group.ambiguous) return;
            Pending entry = pending.remove(group.ids.iterator().next());
            removeCandidate(entry);
            if (!entry.attribution.isKnown()) return;
            connection = new Connection(entry.attribution);
            connections.add(connection);
        }
        // Burp calls are outside our monitor: unloading never waits for registration to finish.
        try {
            connection.attach(creation.proxyWebSocket().registerProxyMessageHandler(connection));
        } catch (RuntimeException | Error e) {
            connection.stop();
            throw e;
        }
    }

    /** Stop callbacks immediately without invoking any potentially blocking Burp operation. */
    synchronized void stop() {
        closed = true;
        pending.clear();
        candidates.clear();
        seenKeys.clear();
        for (Connection connection : connections) connection.active.set(false);
    }

    @Override
    public void close() {
        List<Connection> active;
        synchronized (this) {
            stop();
            active = List.copyOf(connections);
            connections.clear();
        }
        for (Connection connection : active) connection.stop();
    }

    private final class Connection implements ProxyMessageHandler {
        private final Attribution attribution;
        private final AtomicBoolean active = new AtomicBoolean(true);
        private final AtomicReference<Registration> registration = new AtomicReference<>();

        Connection(Attribution attribution) {
            this.attribution = attribution;
        }

        void attach(Registration value) {
            registration.set(value);
            if (!active.get()) deregister();
        }

        void stop() {
            active.set(false);
            synchronized (WebSocketHighlighter.this) {
                connections.remove(this);
            }
            deregister();
        }

        private void deregister() {
            Registration value = registration.getAndSet(null);
            if (value != null) value.deregister();
        }

        @Override
        public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage message) {
            if (active.get()) attribution.annotate(message.annotations());
            return TextMessageReceivedAction.continueWith(message.payload());
        }

        @Override
        public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage message) {
            return TextMessageToBeSentAction.continueWith(message.payload());
        }

        @Override
        public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage message) {
            if (active.get()) attribution.annotate(message.annotations());
            return BinaryMessageReceivedAction.continueWith(message.payload());
        }

        @Override
        public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage message) {
            return BinaryMessageToBeSentAction.continueWith(message.payload());
        }

        @Override
        public void onClose() {
            stop();
        }
    }
}
