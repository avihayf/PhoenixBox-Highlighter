package burp;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Decides which address each marked container listens on. Pure apart from the injected probe.
 *
 * <p>Per container, in order: its pin (never falls back), the address it had last time, then the
 * lowest usable automatic port on the Burp preset's IP from {@link #AUTO_START}. Automatic ports
 * start well above 8081–8090, the range local dev servers tend to use.
 */
final class AddressAllocator {

    static final int AUTO_START = 18080;
    static final int AUTO_SPAN = 1000;

    /** A marked container, as PhoenixBox asked for it. */
    record Request(String id, String name, String color, ListenerAddress pin, ListenerAddress preferred) {
    }

    /** The outcome for one container. {@code adopted} marks a user's own listener we must never touch. */
    record Assignment(ListenerAddress address, boolean adopted, boolean allInterfaces, String error) {

        static Assignment ok(ListenerAddress address) {
            return new Assignment(address, false, false, null);
        }

        static Assignment adopt(ListenerAddress address, boolean allInterfaces) {
            return new Assignment(address, true, allInterfaces, null);
        }

        static Assignment failed(String error) {
            return new Assignment(null, false, false, error);
        }

        boolean isOk() {
            return address != null;
        }
    }

    private final ListenerAddress preset;
    private final ListenerAddress control;
    private final List<ListenerConfig.Entry> userListeners;
    private final Set<ListenerAddress> owned;
    private final AddressProbe probe;

    /**
     * @param userListeners Burp's listeners that this extension did not create.
     * @param owned addresses this extension is already listening on; they skip the probe, which
     *              would otherwise find our own listener and call the address taken.
     */
    AddressAllocator(ListenerAddress preset, ListenerAddress control, List<ListenerConfig.Entry> userListeners,
                     Set<ListenerAddress> owned, AddressProbe probe) {
        this.preset = preset;
        this.control = control;
        this.userListeners = userListeners;
        this.owned = owned;
        this.probe = probe;
    }

    /**
     * @param current each container's address from the previous sync. Pinned containers go first,
     *                since a pin never falls back; then containers keeping their address, so a newly
     *                marked container can never push an existing one off its port.
     */
    Map<String, Assignment> allocate(List<Request> requests, Map<String, ListenerAddress> current) {
        List<Request> ordered = new ArrayList<>(requests);
        ordered.sort(Comparator
                .comparing((Request r) -> r.pin() != null ? 0 : current.containsKey(r.id()) ? 1 : 2)
                .thenComparing(Request::id));

        Set<ListenerAddress> taken = new HashSet<>();
        Map<String, Assignment> result = new LinkedHashMap<>();

        for (Request request : ordered) {
            Assignment assignment = request.pin() != null
                    ? pinned(request.pin(), taken)
                    : automatic(request, current.get(request.id()), taken);

            if (assignment.isOk()) {
                taken.add(assignment.address());
            }
            result.put(request.id(), assignment);
        }

        return result;
    }

    private Assignment pinned(ListenerAddress pin, Set<ListenerAddress> taken) {
        if (pin.equals(preset)) {
            return Assignment.failed(pin + " is the Burp preset address and can't be pinned");
        }
        if (pin.equals(control)) {
            return Assignment.failed(pin + " is the Highlighter's control address");
        }
        if (taken.contains(pin)) {
            return Assignment.failed(pin + " is already pinned by another container");
        }

        // A listener the user built at that address is adopted as-is, whatever its settings.
        for (ListenerConfig.Entry entry : userListeners) {
            if (entry.overlaps(pin)) {
                return Assignment.adopt(pin, entry.isAllInterfaces());
            }
        }

        String problem = problemWith(pin);
        return problem == null ? Assignment.ok(pin) : Assignment.failed(problem);
    }

    private Assignment automatic(Request request, ListenerAddress currentAddress, Set<ListenerAddress> taken) {
        for (ListenerAddress candidate : preferenceOrder(request, currentAddress)) {
            if (usable(candidate, taken)) {
                return Assignment.ok(candidate);
            }
        }

        for (int port = AUTO_START; port < AUTO_START + AUTO_SPAN && port <= 65535; port++) {
            ListenerAddress candidate = preset.withPort(port);
            if (usable(candidate, taken)) {
                return Assignment.ok(candidate);
            }
        }

        return Assignment.failed("no free port on " + preset.host() + " between " + AUTO_START + " and "
                + (AUTO_START + AUTO_SPAN - 1));
    }

    /** The address held right now, then the one remembered from an earlier session. */
    private static List<ListenerAddress> preferenceOrder(Request request, ListenerAddress currentAddress) {
        List<ListenerAddress> order = new ArrayList<>();
        if (currentAddress != null) {
            order.add(currentAddress);
        }
        if (request.preferred() != null && !request.preferred().equals(currentAddress)) {
            order.add(request.preferred());
        }
        return order;
    }

    private boolean usable(ListenerAddress candidate, Set<ListenerAddress> taken) {
        return !candidate.equals(preset)
                && !candidate.equals(control)
                && !taken.contains(candidate)
                && userListeners.stream().noneMatch(entry -> entry.overlaps(candidate))
                && problemWith(candidate) == null;
    }

    /** {@code null} when a listener can be opened there, otherwise why not. */
    private String problemWith(ListenerAddress address) {
        if (owned.contains(address)) {
            return null;
        }

        switch (probe.probe(address)) {
            case FREE:
                return null;
            case NOT_LOCAL:
                return address.host() + " is not an address of the machine Burp runs on";
            default:
                return address + " is in use by another program";
        }
    }
}
