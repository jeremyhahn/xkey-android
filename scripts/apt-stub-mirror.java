// apt-stub-mirror: a loopback HTTP server for scripts/apt-retry-test.sh.
// It serves the files of one directory (a flat apt repository) and answers
// the first FAIL_N requests with HTTP 500, as a mirror with a transient
// fault does; FAIL_N -1 answers every request with 500. It binds 127.0.0.1
// on a free port and writes the port to PORT_FILE once it listens.
//
// Usage: java scripts/apt-stub-mirror.java DIR FAIL_N PORT_FILE
// Needs a JDK 11+ (single-file source launch); the images have /opt/jbr.

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

public class AptStubMirror {
    public static void main(String[] args) throws Exception {
        Path dir = Path.of(args[0]).toAbsolutePath().normalize();
        int failN = Integer.parseInt(args[1]);
        Path portFile = Path.of(args[2]);
        AtomicInteger served = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            int n = served.incrementAndGet();
            String path = exchange.getRequestURI().getPath();
            Path file = dir.resolve(path.substring(1)).normalize();
            int status;
            byte[] body;
            if (failN < 0 || n <= failN) {
                status = 500;
                body = "stub: transient fault\n".getBytes();
            } else if (file.startsWith(dir) && Files.isRegularFile(file)) {
                status = 200;
                body = Files.readAllBytes(file);
            } else {
                status = 404;
                body = new byte[0];
            }
            System.err.println("apt-stub-mirror: " + n + " " + exchange.getRequestMethod() + " " + path + " " + status);
            boolean head = "HEAD".equals(exchange.getRequestMethod());
            exchange.sendResponseHeaders(status, head || body.length == 0 ? -1 : body.length);
            if (!head && body.length > 0) {
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
            exchange.close();
        });
        server.start();
        Path tmp = Path.of(portFile + ".tmp");
        Files.writeString(tmp, Integer.toString(server.getAddress().getPort()));
        Files.move(tmp, portFile);
    }
}
