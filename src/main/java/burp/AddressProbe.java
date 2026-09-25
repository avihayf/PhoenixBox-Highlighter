package burp;

import java.io.IOException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Locale;

/** Checks whether this machine can open a new listener at an address. */
interface AddressProbe {

    enum Result { FREE, IN_USE, NOT_LOCAL }

    Result probe(ListenerAddress address);

    /**
     * Whether something accepts connections there. Used to confirm a listener Burp was just told to
     * open is really up, which is a connect-only check: binding would race Burp for the port.
     */
    boolean answers(ListenerAddress address);

    /**
     * The real probe. Two checks, because either alone misses a case:
     *
     * <ul>
     *   <li>A <b>connect</b> test catches anything already answering, including a dev server bound
     *       to all interfaces.
     *   <li>A <b>strict bind</b> test, with address reuse off, catches the rest. Java turns reuse on
     *       by default outside Windows, and with it on macOS lets {@code 127.0.0.1:P} bind over
     *       another process's {@code *:P} and silently take its local traffic.
     * </ul>
     */
    final class Sockets implements AddressProbe {

        private static final int CONNECT_TIMEOUT_MS = 250;

        @Override
        public boolean answers(ListenerAddress address) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(InetAddress.getByName(address.host()), address.port()),
                        CONNECT_TIMEOUT_MS);
                return true;
            } catch (IOException e) {
                return false;
            }
        }

        @Override
        public Result probe(ListenerAddress address) {
            InetAddress ip;
            try {
                ip = InetAddress.getByName(address.host());
            } catch (IOException e) {
                return Result.NOT_LOCAL;
            }

            if (answers(address)) {
                return Result.IN_USE;
            }

            try (ServerSocket server = new ServerSocket()) {
                server.setReuseAddress(false);
                server.bind(new InetSocketAddress(ip, address.port()));
                return Result.FREE;
            } catch (BindException e) {
                String message = String.valueOf(e.getMessage()).toLowerCase(Locale.ROOT);
                return message.contains("assign") ? Result.NOT_LOCAL : Result.IN_USE;
            } catch (IOException e) {
                return Result.IN_USE;
            }
        }
    }
}
