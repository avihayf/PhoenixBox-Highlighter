package burp;

import java.util.HashMap;
import java.util.Map;

/**
 * Which container each listener belongs to. Read on the proxy hot path, so a sync swaps in a new
 * immutable snapshot rather than mutating one that readers are using.
 */
final class ContainerRegistry {

    record Container(String id, String name, String color) {
    }

    private record Snapshot(Map<ListenerAddress, Container> byAddress, Map<Integer, Container> byAllInterfacesPort) {
    }

    private volatile Snapshot snapshot = new Snapshot(Map.of(), Map.of());

    /**
     * @param byAddress containers on a listener bound to one IP.
     * @param byAllInterfacesPort containers adopted onto a user's all-interfaces listener, which is
     *                            matched on port alone because it answers on every IP.
     */
    void replace(Map<ListenerAddress, Container> byAddress, Map<Integer, Container> byAllInterfacesPort) {
        snapshot = new Snapshot(Map.copyOf(byAddress), Map.copyOf(byAllInterfacesPort));
    }

    void clear() {
        replace(new HashMap<>(), new HashMap<>());
    }

    /** The container for a request, from Burp's {@code listenerInterface()}, e.g. {@code "127.0.0.1:18080"}. */
    Container lookup(String listenerInterface) {
        ListenerAddress address = ListenerAddress.tryParse(listenerInterface);
        if (address == null) {
            return null;
        }

        Snapshot current = snapshot;
        Container exact = current.byAddress().get(address);
        return exact != null ? exact : current.byAllInterfacesPort().get(address.port());
    }

    int size() {
        Snapshot current = snapshot;
        return current.byAddress().size() + current.byAllInterfacesPort().size();
    }
}
