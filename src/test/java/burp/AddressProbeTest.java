package burp;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real sockets on loopback: these behaviours are the operating system's, not ours to mock. */
class AddressProbeTest {

    private final AddressProbe probe = new AddressProbe.Sockets();

    @Test
    void reportsAPortSomethingListensOn() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            ListenerAddress address = new ListenerAddress("127.0.0.1", server.getLocalPort());
            assertEquals(AddressProbe.Result.IN_USE, probe.probe(address));
            assertTrue(probe.answers(address));
        }
    }

    @Test
    void reportsAPortADevServerHoldsOnAllInterfaces() throws Exception {
        try (ServerSocket server = new ServerSocket()) {
            server.bind(new InetSocketAddress(0));
            assertEquals(AddressProbe.Result.IN_USE,
                    probe.probe(new ListenerAddress("127.0.0.1", server.getLocalPort())));
        }
    }

    @Test
    void reportsAFreePortAsFree() throws Exception {
        int port;
        try (ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            port = server.getLocalPort();
        }
        ListenerAddress address = new ListenerAddress("127.0.0.1", port);
        assertEquals(AddressProbe.Result.FREE, probe.probe(address));
        assertFalse(probe.answers(address));
    }

    @Test
    void treatsAPortWhoseListenerJustClosedAsFree() throws Exception {
        // Closing the accepted side first leaves the listener's port in TIME_WAIT, as when a
        // container's listener is removed while the browser still had a connection open.
        int port;
        try (ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
             Socket client = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort())) {
            port = server.getLocalPort();
            try (Socket accepted = server.accept()) {
                accepted.getOutputStream().write(1);
            }
            InputStream in = client.getInputStream();
            in.read();
            in.read(); // end of stream: the server side has closed first
        }

        assertEquals(AddressProbe.Result.FREE, probe.probe(new ListenerAddress("127.0.0.1", port)));
    }

    @Test
    void reportsAnIpThatIsNotOnThisMachine() {
        // TEST-NET-1 (RFC 5737) is never assigned to a real interface.
        assertEquals(AddressProbe.Result.NOT_LOCAL, probe.probe(new ListenerAddress("192.0.2.1", 18080)));
    }
}
