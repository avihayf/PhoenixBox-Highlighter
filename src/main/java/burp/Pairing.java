package burp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

/** The pairing token and the one-line string the user copies from Burp into PhoenixBox. */
final class Pairing {

    static final String PREFIX = "phx1";

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
     * Control tokens travel over HTTP, so control traffic must stay on loopback even when
     * Burp's proxy accepts LAN clients. Keep an existing loopback address for local discovery.
     */
    static String bindHost(List<ListenerConfig.Entry> listeners) {
        if (!listeners.isEmpty()) {
            String host = listeners.get(0).boundHost();
            try {
                if (host != null && InetAddress.getByName(host).isLoopbackAddress()) return host;
            } catch (UnknownHostException ignored) {
                // A bad proxy address must never broaden the control endpoint's exposure.
            }
        }
        return ListenerAddress.LOOPBACK;
    }
}
