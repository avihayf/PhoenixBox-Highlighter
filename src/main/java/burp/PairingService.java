package burp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * Who may drive the control server.
 *
 * <p>PhoenixBox pairs itself: it finds this extension and asks, and the user answers once, in Burp,
 * with Allow or Deny. That click is the security gate. Without it any other Firefox extension, or
 * any local program, could pair and make Burp open listeners wherever it liked.
 *
 * <p>Each approved PhoenixBox (one per Firefox profile, told apart by a random client ID it keeps)
 * gets its own token, so one can be revoked without the others. The manual pairing string's token
 * stays valid too, for when discovery cannot find Burp.
 *
 * <p>Read by Burp's UI thread, so everything that thread reads is a volatile snapshot, never a
 * value behind this object's lock.
 */
final class PairingService {

    /** A pairing request waits this long for an answer before it can be asked again. */
    static final long PENDING_TIMEOUT_MS = 120_000;

    /**
     * How long a denial is remembered. PhoenixBox never asks again on its own after a denial, only
     * when the user presses Connect, so this only stops something else asking over and over.
     */
    static final long DENIAL_MS = 120_000;

    private static final Pattern CLIENT_ID = Pattern.compile("[A-Za-z0-9_-]{16,64}");
    private static final Pattern CONTROL_CHARACTERS = Pattern.compile("\\p{Cntrl}");
    private static final int MAX_LABEL_LENGTH = 64;

    /** Where the approved clients are kept: Burp's user preferences, so they outlive the project. */
    interface Store {
        String get();

        void set(String json);
    }

    /** Asks the user. Must not block: it is called while a control-server request is waiting. */
    interface Prompt {
        void ask(Pending request);
    }

    record Client(String id, String label, String origin, String token) {
    }

    record Pending(String id, String label, String origin, long since) {
    }

    enum Status { APPROVED, PENDING, DENIED, BUSY, INVALID }

    record Result(Status status, String token) {
    }

    private final Store store;
    private final LongSupplier clock;
    private volatile Prompt prompt = request -> { };

    private volatile Map<String, Client> clients = Map.of();
    private volatile Pending pending;
    /** Client ID to when it was denied. */
    private final Map<String, Long> denied = new HashMap<>();
    private volatile String manualToken;

    PairingService(Store store, String manualToken, LongSupplier clock) {
        this.store = store;
        this.manualToken = manualToken;
        this.clock = clock;
        load();
    }

    void setPrompt(Prompt prompt) {
        this.prompt = prompt;
    }

    /**
     * A PhoenixBox asking to pair.
     *
     * @param origin the request's {@code Origin}, {@code moz-extension://<uuid>}. An approved client
     *               must keep asking from the same one, so another extension that somehow learned
     *               its client ID still gets nothing.
     */
    synchronized Result request(String id, String label, String origin) {
        if (id == null || !CLIENT_ID.matcher(id).matches() || origin == null) {
            return new Result(Status.INVALID, null);
        }

        Client known = clients.get(id);
        if (known != null) {
            return known.origin().equals(origin)
                    ? new Result(Status.APPROVED, known.token())
                    : new Result(Status.DENIED, null);
        }
        Long deniedAt = denied.get(id);
        if (deniedAt != null) {
            if (clock.getAsLong() - deniedAt <= DENIAL_MS) {
                return new Result(Status.DENIED, null);
            }
            denied.remove(id);
        }

        Pending current = pending;
        if (current != null && clock.getAsLong() - current.since() > PENDING_TIMEOUT_MS) {
            current = null;
            pending = null;
        }
        if (current != null) {
            return new Result(current.id().equals(id) ? Status.PENDING : Status.BUSY, null);
        }

        Pending asked = new Pending(id, cleanLabel(label), origin, clock.getAsLong());
        pending = asked;
        prompt.ask(asked);
        return new Result(Status.PENDING, null);
    }

    /** The user's answer. Ignored unless it is about the request still waiting. */
    synchronized void decide(String id, boolean allow) {
        Pending current = pending;
        if (current == null || !current.id().equals(id)) {
            return;
        }

        pending = null;
        if (!allow) {
            denied.put(id, clock.getAsLong());
            return;
        }

        Map<String, Client> next = new LinkedHashMap<>(clients);
        next.put(id, new Client(id, current.label(), current.origin(), Pairing.newToken()));
        clients = java.util.Collections.unmodifiableMap(next);
        persist();
    }

    synchronized void revoke(String id) {
        Map<String, Client> next = new LinkedHashMap<>(clients);
        if (next.remove(id) != null) {
            clients = java.util.Collections.unmodifiableMap(next);
            persist();
        }
    }

    /** Revokes every pairing, the manual pairing string included. */
    synchronized void revokeAll(String newManualToken) {
        clients = Map.of();
        denied.clear();
        manualToken = newManualToken;
        persist();
    }

    /** Lock-free: the request path and Burp's UI thread both call this. */
    boolean isAuthorized(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return false;
        }
        byte[] given = authorizationHeader.substring("Bearer ".length()).getBytes(StandardCharsets.UTF_8);

        boolean match = false;
        String manual = manualToken;
        if (manual != null && !manual.isEmpty()) {
            match |= MessageDigest.isEqual(given, manual.getBytes(StandardCharsets.UTF_8));
        }
        for (Client client : clients.values()) {
            match |= MessageDigest.isEqual(given, client.token().getBytes(StandardCharsets.UTF_8));
        }
        return match;
    }

    /** Lock-free, for Burp's UI thread. */
    Pending pending() {
        Pending current = pending;
        return current != null && clock.getAsLong() - current.since() > PENDING_TIMEOUT_MS ? null : current;
    }

    /** Lock-free, for Burp's UI thread. */
    List<Client> clients() {
        return List.copyOf(clients.values());
    }

    String manualToken() {
        return manualToken;
    }

    static String cleanLabel(String label) {
        String cleaned = label == null ? "" : CONTROL_CHARACTERS.matcher(label).replaceAll("").trim();
        if (cleaned.isEmpty()) {
            return "PhoenixBox";
        }
        return cleaned.codePointCount(0, cleaned.length()) > MAX_LABEL_LENGTH
                ? cleaned.substring(0, cleaned.offsetByCodePoints(0, MAX_LABEL_LENGTH))
                : cleaned;
    }

    private void persist() {
        if (store == null) {
            return;
        }
        List<Object> list = new ArrayList<>();
        for (Client client : clients.values()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("id", client.id());
            entry.put("label", client.label());
            entry.put("origin", client.origin());
            entry.put("token", client.token());
            list.add(entry);
        }
        store.set(Json.write(list));
    }

    private void load() {
        String stored = store == null ? null : store.get();
        if (stored == null) {
            return;
        }
        try {
            List<Object> list = Json.asArray(Json.parse(stored));
            Map<String, Client> loaded = new LinkedHashMap<>();
            if (list != null) {
                for (Object item : list) {
                    Map<String, Object> entry = Json.asObject(item);
                    if (entry != null && entry.get("id") instanceof String id && entry.get("origin") instanceof String origin
                            && entry.get("token") instanceof String token) {
                        Object label = entry.get("label");
                        loaded.put(id, new Client(id, label instanceof String s ? s : "PhoenixBox", origin, token));
                    }
                }
            }
            clients = java.util.Collections.unmodifiableMap(loaded);
        } catch (IllegalArgumentException ignored) {
            // A corrupt record pairs nobody; PhoenixBox simply asks again.
        }
    }
}
