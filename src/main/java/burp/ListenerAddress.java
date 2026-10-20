package burp;

import java.util.Locale;

/**
 * An IP:port a proxy listener is bound to. Listeners are always told apart by both halves, never
 * by port alone, because the same port on two IPs is two different listeners.
 */
record ListenerAddress(String host, int port) {

    static final String LOOPBACK = "127.0.0.1";

    ListenerAddress {
        host = normalizeHost(host);
        if (host.isEmpty()) {
            throw new IllegalArgumentException("missing host");
        }
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port out of range: " + port);
        }
    }

    /**
     * Parses {@code host:port} or {@code [ipv6]:port}, as PhoenixBox sends it and as Burp reports a
     * request's listener interface.
     */
    static ListenerAddress parse(String value) {
        if (value == null) {
            throw new IllegalArgumentException("missing address");
        }

        String trimmed = value.trim();
        int colon = trimmed.lastIndexOf(':');
        if (colon <= 0 || colon == trimmed.length() - 1) {
            throw new IllegalArgumentException("expected host:port, got '" + trimmed + "'");
        }

        String host = trimmed.substring(0, colon);
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        } else if (host.contains(":")) {
            throw new IllegalArgumentException("IPv6 addresses need brackets: '" + trimmed + "'");
        }

        int port;
        try {
            port = Integer.parseInt(trimmed.substring(colon + 1));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("bad port in '" + trimmed + "'");
        }

        return new ListenerAddress(host, port);
    }

    /** {@code null} instead of an exception, for untrusted input. */
    static ListenerAddress tryParse(String value) {
        try {
            return parse(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Whether Burp's "loopback only" mode covers this address. That mode binds 127.0.0.1 alone, so
     * any other loopback IP (127.0.0.2, ::1) needs a specific-address listener instead.
     */
    boolean isDefaultLoopback() {
        return LOOPBACK.equals(host);
    }

    boolean isLoopback() {
        return host.startsWith("127.") || "::1".equals(host);
    }

    ListenerAddress withPort(int newPort) {
        return new ListenerAddress(host, newPort);
    }

    @Override
    public String toString() {
        return (host.contains(":") ? "[" + host + "]" : host) + ":" + port;
    }

    private static String normalizeHost(String host) {
        String h = host == null ? "" : host.trim().toLowerCase(Locale.ROOT);
        return "localhost".equals(h) ? LOOPBACK : h;
    }
}
