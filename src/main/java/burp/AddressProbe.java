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
     * The real probe, in two steps:
     *
     * <ul>
     *   <li>A <b>connect</b> test catches anything already listening. That includes a dev server
     *       bound to all interfaces, which answers on {@code 127.0.0.1} too, so its port is never
     *       taken over even though a reuse-on bind of {@code 127.0.0.1:P} would succeed beside it.
     *   <li>A <b>bind</b> test, with address reuse on as Burp itself binds, then tells a usable
     *       address from one that is not on this machine. Reuse must be on: a port whose listener
     *       just closed keeps connections in TIME_WAIT for a while, and a reuse-off bind fails on
     *       those even though nothing listens — which stopped containers getting their old port
     *       back after the extension was reloaded.
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
                server.setReuseAddress(true);
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
