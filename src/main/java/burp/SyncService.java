package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

/**
 * Turns PhoenixBox's desired state into listeners, container attribution and a reply.
 *
 * <p>Every sync carries the full list of marked containers rather than a change, so whatever was
 * lost in between (a dropped request, a restart on either side) is repaired by the next one.
 */
final class SyncService {

    static final int PROTOCOL = 1;

    /**
     * With no sync for this long, PhoenixBox is assumed gone (Firefox quit or crashed) and our
     * listeners are closed. PhoenixBox syncs every 10 s, so this tolerates two missed beats.
     */
    static final long LEASE_MS = 30_000;

    /** A sanity bound on one request, not a limit on how many containers a user may mark. */
    static final int MAX_CONTAINERS = 1000;

    static final int MAX_NAME_LENGTH = 64;
    static final int MAX_ID_LENGTH = 128;

    /** How long to wait for Burp to bring a new listener up before reporting it as failed. */
    static final long LISTENER_START_TIMEOUT_MS = 2_000;

    static final Set<String> COLORS = Set.of("blue", "cyan", "green", "yellow", "orange", "red", "pink", "magenta");

    private static final Pattern CONTROL_CHARACTERS = Pattern.compile("\\p{Cntrl}");

    /** Rejects a malformed sync. The message goes back to PhoenixBox verbatim. */
    static final class BadSync extends RuntimeException {
        BadSync(String message) {
            super(message);
        }
    }

    /** One row for the Burp tab. */
    record Row(String name, String color, String address, String error, boolean adopted) {
    }

    private final ListenerManager manager;
    private final ContainerRegistry registry;
    private final KnownNames knownNames;
    private final AddressProbe probe;
    private volatile ListenerAddress control;
    private final LongSupplier clock;

    private Map<String, ListenerAddress> current = new HashMap<>();

    // Read by Burp's UI thread without taking this object's lock. A sync holds the lock while
    // Burp applies the listener change, and Burp does that by waiting on its UI thread; if the UI
    // thread then waited for the lock, both would hang, and Burp's whole UI with them.
    private volatile List<Row> rows = List.of();
    private volatile long lastSync = -1;

    SyncService(ListenerManager manager, ContainerRegistry registry, KnownNames knownNames, AddressProbe probe,
                ListenerAddress control, LongSupplier clock) {
        this.manager = manager;
        this.registry = registry;
        this.knownNames = knownNames;
        this.probe = probe;
        this.control = control;
        this.clock = clock;
    }

    /** The control server's actual address, once it is bound; allocation must never use it. */
    void setControl(ListenerAddress control) {
        this.control = control;
    }

    synchronized Map<String, Object> sync(Map<String, Object> body) {
        if (body == null || !(body.get("protocol") instanceof Number)
                || ((Number) body.get("protocol")).intValue() != PROTOCOL) {
            throw new BadSync("unsupported protocol; this Highlighter speaks protocol " + PROTOCOL);
        }

        // Unpairing: PhoenixBox is about to fall back to the legacy colour header, so leave paired
        // mode now rather than when the lease runs out, or that header would not be stripped.
        if (Boolean.TRUE.equals(body.get("release"))) {
            release();
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("protocol", (long) PROTOCOL);
            response.put("jar", ContainerHighlighter.VERSION);
            response.put("assignments", new LinkedHashMap<String, Object>());
            return response;
        }

        ListenerAddress preset = parsePreset(body.get("preset"));
        List<AddressAllocator.Request> requests = parseContainers(body.get("containers"));

        AddressAllocator allocator = new AddressAllocator(
                preset, control, manager.userListeners(), manager.owned(), probe);
        Map<String, AddressAllocator.Assignment> assignments = allocator.allocate(requests, current);

        Set<ListenerAddress> ownedWanted = new LinkedHashSet<>();
        assignments.values().stream()
                .filter(a -> a.isOk() && !a.adopted())
                .forEach(a -> ownedWanted.add(a.address()));

        Map<String, String> failures = new HashMap<>();
        try {
            Set<ListenerAddress> opened = manager.apply(ownedWanted);
            // Checked every time, not just when newly opened: PhoenixBox only routes to an address
            // reported ok, so an owned listener that has since died must not be reported ok again.
            for (ListenerAddress address : ownedWanted) {
                boolean up = opened.contains(address) ? waitUntilAnswering(address) : probe.answers(address);
                if (!up) {
                    failures.put(address.toString(), "Burp did not open a listener on " + address);
                }
            }
        } catch (RuntimeException e) {
            // Burp refused the settings change: nothing new is up, so nothing may be routed to it.
            String reason = "Burp refused the listener change: " + e.getMessage();
            ownedWanted.forEach(address -> failures.put(address.toString(), reason));
        }

        return publish(requests, assignments, failures);
    }

    /** Closes everything once PhoenixBox has been silent for the whole lease. */
    synchronized void expireIfIdle() {
        if (lastSync < 0 || clock.getAsLong() - lastSync < LEASE_MS) {
            return;
        }
        release();
    }

    /**
     * Leaves paired mode now: after a pairing is revoked in Burp, that PhoenixBox falls back to the
     * legacy colour header, which is only stripped while unpaired. A PhoenixBox still paired
     * re-enters paired mode with its next sync. Never call this on Burp's UI thread: it changes
     * Burp's listeners, which Burp does on that thread.
     */
    synchronized void releaseNow() {
        release();
    }

    /** Back to unpaired: no container listeners, and the legacy colour header handled again. */
    private void release() {
        lastSync = -1;
        current = new HashMap<>();
        rows = List.of();
        registry.clear();
        manager.removeAll();
    }

    /**
     * Whether a paired PhoenixBox is driving highlighting: it synced within the lease and has not
     * unpaired. PhoenixBox sends no headers then, so none are read or stripped. Lock-free: called
     * for every proxied request.
     */
    boolean isPaired() {
        return lastSync >= 0;
    }

    /** Lock-free: safe to call from Burp's UI thread while a sync is running. */
    List<Row> rows() {
        return rows;
    }

    /** Lock-free: safe to call from Burp's UI thread while a sync is running. */
    long lastSync() {
        return lastSync;
    }

    /** Lock-free: safe to call from Burp's UI thread while a sync is running. */
    int listenerCount() {
        return registry.size();
    }

    private Map<String, Object> publish(List<AddressAllocator.Request> requests,
                                        Map<String, AddressAllocator.Assignment> assignments,
                                        Map<String, String> failures) {
        Map<ListenerAddress, ContainerRegistry.Container> byAddress = new HashMap<>();
        Map<Integer, ContainerRegistry.Container> byPort = new HashMap<>();
        Map<String, ListenerAddress> nextCurrent = new HashMap<>();
        Map<String, Object> reply = new LinkedHashMap<>();
        List<Row> nextRows = new ArrayList<>();
        List<String> names = new ArrayList<>();

        for (AddressAllocator.Request request : requests) {
            AddressAllocator.Assignment assignment = assignments.get(request.id());
            String error = assignment.error();
            if (error == null && failures.containsKey(assignment.address().toString())) {
                error = failures.get(assignment.address().toString());
            }

            Map<String, Object> entry = new LinkedHashMap<>();
            if (error == null) {
                ContainerRegistry.Container container =
                        new ContainerRegistry.Container(request.id(), request.name(), request.color());
                if (assignment.allInterfaces()) {
                    byPort.put(assignment.address().port(), container);
                } else {
                    byAddress.put(assignment.address(), container);
                }
                nextCurrent.put(request.id(), assignment.address());
                names.add(request.name());

                entry.put("status", "ok");
                entry.put("address", assignment.address().toString());
            } else {
                entry.put("status", "error");
                entry.put("address", null);
                entry.put("error", error);
            }
            reply.put(request.id(), entry);
            nextRows.add(new Row(request.name(), request.color(),
                    error == null ? assignment.address().toString() : null, error, assignment.adopted()));
        }

        registry.replace(byAddress, byPort);
        knownNames.addAll(names);
        current = nextCurrent;
        rows = List.copyOf(nextRows);
        lastSync = clock.getAsLong();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("protocol", (long) PROTOCOL);
        response.put("jar", ContainerHighlighter.VERSION);
        response.put("assignments", reply);
        return response;
    }

    private boolean waitUntilAnswering(ListenerAddress address) {
        long deadline = System.nanoTime() + LISTENER_START_TIMEOUT_MS * 1_000_000;
        while (true) {
            if (probe.answers(address)) {
                return true;
            }
            if (System.nanoTime() > deadline) {
                return false;
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    private static ListenerAddress parsePreset(Object value) {
        Map<String, Object> preset = Json.asObject(value);
        if (preset == null || !(preset.get("host") instanceof String) || !(preset.get("port") instanceof Number)) {
            throw new BadSync("preset must be {host, port}");
        }
        try {
            return new ListenerAddress((String) preset.get("host"), ((Number) preset.get("port")).intValue());
        } catch (IllegalArgumentException e) {
            throw new BadSync("bad preset: " + e.getMessage());
        }
    }

    private static List<AddressAllocator.Request> parseContainers(Object value) {
        List<Object> containers = Json.asArray(value);
        if (containers == null) {
            throw new BadSync("containers must be an array");
        }
        if (containers.size() > MAX_CONTAINERS) {
            throw new BadSync("too many containers");
        }

        List<AddressAllocator.Request> requests = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Object item : containers) {
            Map<String, Object> container = Json.asObject(item);
            if (container == null || !(container.get("id") instanceof String)) {
                throw new BadSync("each container needs an id");
            }

            String id = ((String) container.get("id")).trim();
            if (id.isEmpty() || id.length() > MAX_ID_LENGTH || !seen.add(id)) {
                throw new BadSync("bad or duplicate container id");
            }

            String name = cleanName(container.get("name"));
            Object colorValue = container.get("color");
            String color = colorValue instanceof String && COLORS.contains(colorValue) ? (String) colorValue : null;

            ListenerAddress pin = null;
            if (container.get("pin") instanceof String) {
                pin = ListenerAddress.tryParse((String) container.get("pin"));
                if (pin == null) {
                    throw new BadSync("container " + id + " has an invalid pin");
                }
            }
            ListenerAddress preferred = container.get("preferred") instanceof String
                    ? ListenerAddress.tryParse((String) container.get("preferred"))
                    : null;

            requests.add(new AddressAllocator.Request(id, name == null ? id : name, color, pin, preferred));
        }
        return requests;
    }

    /**
     * The name ends up in notes and Repeater tab labels, and arrives from the network, so control
     * characters go and the sender's length cap is applied again rather than trusted.
     */
    static String cleanName(Object value) {
        if (!(value instanceof String)) {
            return null;
        }
        String cleaned = CONTROL_CHARACTERS.matcher((String) value).replaceAll("").trim();
        if (cleaned.isEmpty()) {
            return null;
        }
        return cleaned.codePointCount(0, cleaned.length()) > MAX_NAME_LENGTH
                ? cleaned.substring(0, cleaned.offsetByCodePoints(0, MAX_NAME_LENGTH))
                : cleaned;
    }
}
