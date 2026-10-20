package burp;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

/** The pairing token and the one-line string the user copies from Burp into PhoenixBox. */
final class Pairing {

    static final String PREFIX = "phx1";

    /**
     * Stands in for "whichever IP you reach Burp's proxy on" when the control server listens on all
     * interfaces and cannot know which one Firefox uses. PhoenixBox substitutes the preset's host.
     */
    static final String ANY_HOST = "0.0.0.0";

    private static final SecureRandom RANDOM = new SecureRandom();

    private Pairing() {
    }

    static String newToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String pairingString(String host, int port, String token) {
        String shownHost = host.contains(":") ? "[" + host + "]" : host;
        return PREFIX + ":" + shownHost + ":" + port + ":" + token;
    }

    /**
     * Where the control server listens: the same way as the user's first proxy listener, so it is
     * reachable exactly where Burp's proxy is. Loopback when there is no listener to copy.
     */
    static String bindHost(List<ListenerConfig.Entry> listeners) {
        if (listeners.isEmpty()) {
            return ListenerAddress.LOOPBACK;
        }

        ListenerConfig.Entry first = listeners.get(0);
        if (first.isAllInterfaces()) {
            return ANY_HOST;
        }
        String host = first.boundHost();
        return host == null || host.isEmpty() ? ListenerAddress.LOOPBACK : host;
    }
}
