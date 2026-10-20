package burp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads and rewrites Burp's {@code proxy.request_listeners} project setting, as exported by
 * {@code exportProjectOptionsAsJson("proxy.request_listeners")}.
 *
 * <p>Pure string-in, string-out so the rewrite rules are testable without Burp: only the listeners
 * named for removal are touched, and every other field of every other listener passes through
 * exactly as Burp exported it.
 */
final class ListenerConfig {

    static final String PATH = "proxy.request_listeners";

    static final String MODE_LOOPBACK = "loopback_only";
    static final String MODE_ALL = "all_interfaces";
    static final String MODE_SPECIFIC = "specific_address";

    private ListenerConfig() {
    }

    /** One configured listener, as far as address allocation cares. */
    record Entry(int port, String mode, String specificAddress, boolean running) {

        /** Whether a listener bound here would clash with {@code address}. */
        boolean overlaps(ListenerAddress address) {
            if (address.port() != port) {
                return false;
            }
            if (MODE_ALL.equals(mode)) {
                return true;
            }
            if (MODE_SPECIFIC.equals(mode)) {
                return specificAddress != null && specificAddress.equalsIgnoreCase(address.host());
            }
            // Loopback-only, and any mode Burp adds later that we do not know: assume 127.0.0.1.
            return address.isDefaultLoopback();
        }

        /** Whether this entry is exactly the listener at {@code address} (not merely overlapping). */
        boolean isExactly(ListenerAddress address) {
            if (address.port() != port) {
                return false;
            }
            if (MODE_SPECIFIC.equals(mode)) {
                return specificAddress != null && specificAddress.equalsIgnoreCase(address.host());
            }
            return MODE_LOOPBACK.equals(mode) && address.isDefaultLoopback();
        }

        boolean isAllInterfaces() {
            return MODE_ALL.equals(mode);
        }

        /** The host this listener's requests report through {@code listenerInterface()}, or null for all interfaces. */
        String boundHost() {
            if (MODE_SPECIFIC.equals(mode)) {
                return specificAddress;
            }
            return MODE_ALL.equals(mode) ? null : ListenerAddress.LOOPBACK;
        }
    }

    static List<Entry> parse(String exportJson) {
        List<Entry> entries = new ArrayList<>();
        for (Map<String, Object> raw : rawListeners(Json.parse(exportJson))) {
            Entry entry = toEntry(raw);
            if (entry != null) {
                entries.add(entry);
            }
        }
        return entries;
    }

    /**
     * The import JSON that removes the listeners at {@code remove} and adds new ones at {@code add}.
     * A listener is removed only when it is exactly one of those addresses, so a user's
     * all-interfaces listener on the same port can never be taken down by mistake.
     */
    static String rewrite(String exportJson, Set<ListenerAddress> remove, Set<ListenerAddress> add) {
        Object root = Json.parse(exportJson);
        List<Object> kept = new ArrayList<>();

        for (Map<String, Object> raw : rawListeners(root)) {
            Entry entry = toEntry(raw);
            boolean ours = entry != null && remove.stream().anyMatch(entry::isExactly);
            if (!ours) {
                kept.add(raw);
            }
        }

        for (ListenerAddress address : add) {
            kept.add(newListener(address));
        }

        Map<String, Object> proxy = new LinkedHashMap<>();
        proxy.put("request_listeners", kept);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("proxy", proxy);
        return Json.write(out);
    }

    /**
     * A fresh listener with Burp's defaults. Deliberately not copied from the user's own listener:
     * that one may carry invisible proxying, redirects or a custom certificate, none of which should
     * silently apply to container traffic.
     */
    static Map<String, Object> newListener(ListenerAddress address) {
        Map<String, Object> listener = new LinkedHashMap<>();
        listener.put("certificate_mode", "per_host");
        listener.put("custom_tls_protocols", new ArrayList<>());
        listener.put("enable_http2", Boolean.TRUE);
        if (address.isDefaultLoopback()) {
            listener.put("listen_mode", MODE_LOOPBACK);
        } else {
            listener.put("listen_mode", MODE_SPECIFIC);
            listener.put("listen_specific_address", address.host());
        }
        listener.put("listener_port", (long) address.port());
        listener.put("running", Boolean.TRUE);
        listener.put("use_custom_tls_protocols", Boolean.FALSE);
        return listener;
    }

    private static List<Map<String, Object>> rawListeners(Object root) {
        Map<String, Object> rootObject = Json.asObject(root);
        Map<String, Object> proxy = rootObject == null ? null : Json.asObject(rootObject.get("proxy"));
        List<Object> listeners = proxy == null ? null : Json.asArray(proxy.get("request_listeners"));

        List<Map<String, Object>> result = new ArrayList<>();
        if (listeners != null) {
            for (Object listener : listeners) {
                Map<String, Object> object = Json.asObject(listener);
                if (object != null) {
                    result.add(object);
                }
            }
        }
        return result;
    }

    private static Entry toEntry(Map<String, Object> raw) {
        Object port = raw.get("listener_port");
        if (!(port instanceof Number)) {
            return null;
        }

        String mode = raw.get("listen_mode") instanceof String ? (String) raw.get("listen_mode") : MODE_LOOPBACK;
        String specific = raw.get("listen_specific_address") instanceof String
                ? ((String) raw.get("listen_specific_address")).trim()
                : null;
        boolean running = !Boolean.FALSE.equals(raw.get("running"));
        return new Entry(((Number) port).intValue(), mode, specific, running);
    }
}
