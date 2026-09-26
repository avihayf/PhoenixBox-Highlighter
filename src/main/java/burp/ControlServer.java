package burp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * The small HTTP endpoint PhoenixBox talks to.
 *
 * <p>Hand-written on {@link ServerSocket} because Burp's bundled Java runtime has no
 * {@code jdk.httpserver}. One request per connection, bounded sizes and read timeouts, since
 * anything on the network path can connect.
 */
final class ControlServer {

    static final int DEFAULT_PORT = 8079;
    static final int LAST_PORT = 8099;

    static final int MAX_HEADER_BYTES = 8 * 1024;
    static final int MAX_BODY_BYTES = 64 * 1024;
    private static final int READ_TIMEOUT_MS = 5_000;

    record Request(String method, String path, Map<String, String> headers, String body) {
    }

    record Response(int status, String body) {
    }

    /** What the endpoint serves, kept apart from sockets so the rules are testable. */
    static final class Handler {

        private final PairingService pairing;
        private final SyncService sync;

        Handler(PairingService pairing, SyncService sync) {
            this.pairing = pairing;
            this.sync = sync;
        }

        Response handle(Request request) {
            // A web page's cross-origin JSON POST is preceded by a preflight. Refusing every
            // preflight means the page never gets to send the real request.
            if ("OPTIONS".equals(request.method())) {
                return error(405, "method not allowed");
            }

            String origin = request.headers().get("origin");
            if (origin != null && !origin.startsWith("moz-extension://")) {
                return error(403, "forbidden origin");
            }

            // Discovery and pairing need no token, only a Firefox extension's Origin, which Firefox
            // sends on every extension POST and a web page cannot set. Pairing still does nothing
            // until the user clicks Allow in Burp.
            if ("POST".equals(request.method()) && "/v1/hello".equals(request.path())) {
                Response refused = requireExtension(request, origin);
                if (refused != null) {
                    return refused;
                }
                Map<String, Object> hello = new LinkedHashMap<>();
                hello.put("app", "phoenixbox-highlighter");
                hello.put("protocol", (long) SyncService.PROTOCOL);
                hello.put("jar", ContainerHighlighter.VERSION);
                return new Response(200, Json.write(hello));
            }

            if ("POST".equals(request.method()) && "/v1/pair".equals(request.path())) {
                Response refused = requireExtension(request, origin);
                if (refused != null) {
                    return refused;
                }
                return pair(request, origin);
            }

            if (!pairing.isAuthorized(request.headers().get("authorization"))) {
                return error(401, "missing or wrong pairing token");
            }

            if ("GET".equals(request.method()) && "/v1/status".equals(request.path())) {
                Map<String, Object> status = new LinkedHashMap<>();
                status.put("protocol", (long) SyncService.PROTOCOL);
                status.put("jar", ContainerHighlighter.VERSION);
                status.put("listeners", (long) sync.listenerCount());
                return new Response(200, Json.write(status));
            }

            if ("POST".equals(request.method()) && "/v1/sync".equals(request.path())) {
                String contentType = request.headers().getOrDefault("content-type", "");
                if (!contentType.toLowerCase(Locale.ROOT).startsWith("application/json")) {
                    return error(415, "expected application/json");
                }

                Map<String, Object> body;
                try {
                    body = Json.asObject(Json.parse(request.body()));
                } catch (IllegalArgumentException e) {
                    return error(400, "body is not valid JSON");
                }

                try {
                    return new Response(200, Json.write(sync.sync(body)));
                } catch (SyncService.BadSync e) {
                    return error(400, e.getMessage());
                }
            }

            return error(404, "not found");
        }

        private Response pair(Request request, String origin) {
            Map<String, Object> body;
            try {
                body = Json.asObject(Json.parse(request.body()));
            } catch (IllegalArgumentException e) {
                return error(400, "body is not valid JSON");
            }
            if (body == null) {
                return error(400, "expected a JSON object");
            }

            Object client = body.get("client");
            Object label = body.get("label");
            PairingService.Result result = pairing.request(
                    client instanceof String ? (String) client : null,
                    label instanceof String ? (String) label : null,
                    origin);

            Map<String, Object> reply = new LinkedHashMap<>();
            switch (result.status()) {
                case APPROVED:
                    reply.put("status", "approved");
                    reply.put("token", result.token());
                    return new Response(200, Json.write(reply));
                case PENDING:
                    reply.put("status", "pending");
                    return new Response(202, Json.write(reply));
                case BUSY:
                    return error(429, "another PhoenixBox is waiting for approval in Burp");
                case DENIED:
                    return error(403, "pairing was denied in Burp");
                default:
                    return error(400, "invalid client id");
            }
        }

        /** Only a Firefox extension may discover or pair: its POSTs carry a moz-extension Origin. */
        private static Response requireExtension(Request request, String origin) {
            if (origin == null || !origin.startsWith("moz-extension://")) {
                return error(403, "only the PhoenixBox extension may pair");
            }
            String contentType = request.headers().getOrDefault("content-type", "");
            if (!contentType.toLowerCase(Locale.ROOT).startsWith("application/json")) {
                return error(415, "expected application/json");
            }
            return null;
        }

        private static Response error(int status, String message) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("error", message);
            return new Response(status, Json.write(body));
        }
    }

    private final Handler handler;
    private final Consumer<String> errorLog;
    private final ExecutorService workers = Executors.newFixedThreadPool(2, runnable -> {
        Thread thread = new Thread(runnable, "phoenixbox-control");
        thread.setDaemon(true);
        return thread;
    });

    private volatile ServerSocket server;

    ControlServer(Handler handler, Consumer<String> errorLog) {
        this.handler = handler;
        this.errorLog = errorLog;
    }

    /**
     * Binds the first usable port from {@link #DEFAULT_PORT} to {@link #LAST_PORT}. Always starting at
     * the default keeps the port, and so the pairing string, the same across reloads.
     *
     * @return the bound port.
     */
    int start(String bindHost) throws IOException {
        return start(bindHost, DEFAULT_PORT, LAST_PORT);
    }

    /**
     * A port is skipped only when something answers on it. The bind itself has address reuse on:
     * with it off, the connections PhoenixBox's syncs leave in TIME_WAIT made the default port look
     * taken after every reload, moving the server, and breaking the pairing, for no reason.
     */
    int start(String bindHost, int firstPort, int lastPort) throws IOException {
        InetAddress bindAddress = InetAddress.getByName(bindHost);
        AddressProbe probe = new AddressProbe.Sockets();

        IOException lastFailure = null;
        for (int port = firstPort; port <= lastPort; port++) {
            if (probe.answers(new ListenerAddress(bindHost, port))) {
                lastFailure = new IOException("port " + port + " is in use");
                continue;
            }

            ServerSocket candidate = new ServerSocket();
            try {
                candidate.setReuseAddress(true);
                candidate.bind(new InetSocketAddress(bindAddress, port));
                server = candidate;
                Thread acceptor = new Thread(this::acceptLoop, "phoenixbox-control-accept");
                acceptor.setDaemon(true);
                acceptor.start();
                return port;
            } catch (IOException e) {
                candidate.close();
                lastFailure = e;
            }
        }
        throw lastFailure == null ? new IOException("no free control port") : lastFailure;
    }

    void stop() {
        ServerSocket current = server;
        server = null;
        if (current != null) {
            try {
                current.close();
            } catch (IOException ignored) {
                // Closing anyway.
            }
        }
        workers.shutdownNow();
    }

    private void acceptLoop() {
        ServerSocket current = server;
        while (current != null && !current.isClosed()) {
            try {
                Socket socket = current.accept();
                workers.submit(() -> serve(socket));
            } catch (SocketException closed) {
                return;
            } catch (IOException e) {
                errorLog.accept("PhoenixBox Highlighter: control connection failed: " + e.getMessage());
            } catch (RuntimeException rejected) {
                // Executor shut down during unload.
                return;
            }
        }
    }

    private void serve(Socket socket) {
        try (socket) {
            socket.setSoTimeout(READ_TIMEOUT_MS);
            Response response;
            try {
                Request request = read(socket.getInputStream());
                response = request == null
                        ? new Response(400, "{\"error\":\"malformed request\"}")
                        : handler.handle(request);
            } catch (RuntimeException e) {
                errorLog.accept("PhoenixBox Highlighter: control request failed: " + e);
                response = new Response(500, "{\"error\":\"internal error\"}");
            }
            write(socket.getOutputStream(), response);
        } catch (IOException ignored) {
            // The client went away.
        }
    }

    /** Parses one HTTP/1.1 request, or returns {@code null} when it is malformed or oversized. */
    static Request read(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int lastFour = 0;
        while (lastFour != 0x0D0A0D0A) { // CR LF CR LF ends the header block
            int b = in.read();
            if (b < 0 || head.size() >= MAX_HEADER_BYTES) {
                return null;
            }
            head.write(b);
            lastFour = (lastFour << 8) | b;
        }

        String[] lines = head.toString(StandardCharsets.ISO_8859_1).split("\r\n");
        String[] requestLine = lines[0].split(" ");
        if (requestLine.length != 3) {
            return null;
        }

        Map<String, String> headers = new HashMap<>();
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.put(lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT),
                        lines[i].substring(colon + 1).trim());
            }
        }

        int length = 0;
        if (headers.containsKey("content-length")) {
            try {
                length = Integer.parseInt(headers.get("content-length"));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        if (length < 0 || length > MAX_BODY_BYTES || headers.containsKey("transfer-encoding")) {
            return null;
        }

        byte[] body = in.readNBytes(length);
        if (body.length != length) {
            return null;
        }

        String path = requestLine[1];
        int query = path.indexOf('?');
        return new Request(requestLine[0], query >= 0 ? path.substring(0, query) : path, headers,
                new String(body, StandardCharsets.UTF_8));
    }

    private static void write(OutputStream out, Response response) throws IOException {
        byte[] body = response.body().getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + response.status() + " " + reason(response.status()) + "\r\n"
                + "Content-Type: application/json\r\n"
                + "Cache-Control: no-store\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "Connection: close\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.ISO_8859_1));
        out.write(body);
        out.flush();
    }

    private static String reason(int status) {
        switch (status) {
            case 200: return "OK";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 202: return "Accepted";
            case 415: return "Unsupported Media Type";
            case 429: return "Too Many Requests";
            default: return "Error";
        }
    }
}
