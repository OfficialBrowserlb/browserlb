import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
 
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
 

class DuplicateLinkGuard {
 
    private static final long THRESHOLD_MILLIS = 2000;
 
    private final ConcurrentHashMap<String, Long> lastSeen = new ConcurrentHashMap<>();
 
   
    boolean checkAndRegister(String sessionId, String url) {
        String key = sessionId + "::" + url;
        long now = System.currentTimeMillis();
        Long previous = lastSeen.put(key, now);
        if (previous != null && (now - previous) < THRESHOLD_MILLIS) {
        
            lastSeen.put(key, previous);
            return false;
        }
        return true;
    }
}
 
class SecurityFilter {
 
    private static final List<Pattern> MALICIOUS_PATTERNS = List.of(
            Pattern.compile("(?i)<script[^>]*>"),
            Pattern.compile("(?i)javascript:"),
            Pattern.compile("(?i)\\b(union|select)\\b.{0,20}\\b(from|table)\\b"),
            Pattern.compile("\\.\\./"),         
            Pattern.compile("(?i)\\bexec(\\s|\\()")
    );
 
    private static final List<String> BLOCKED_HOST_FRAGMENTS = List.of(
            "malware-test.local",
            "phishing-example.test"
    );
 
    boolean isSafe(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
        for (Pattern p : MALICIOUS_PATTERNS) {
            if (p.matcher(url).find()) {
                return false;
            }
        }
        for (String fragment : BLOCKED_HOST_FRAGMENTS) {
            if (url.contains(fragment)) {
                return false;
            }
        }
        return url.startsWith("http://") || url.startsWith("https://");
    }
}
 
class ValidateHandler implements HttpHandler {
 
    private final DuplicateLinkGuard duplicateGuard = new DuplicateLinkGuard();
    private final SecurityFilter securityFilter = new SecurityFilter();
 
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQuery(exchange.getRequestURI().getRawQuery());
        String session = params.getOrDefault("session", "anonymous");
        String url = params.getOrDefault("url", "");
 
        boolean allowed;
        String reason;
 
        if (!securityFilter.isSafe(url)) {
            allowed = false;
            reason = "blocked by security filter (malicious pattern or bad scheme)";
        } else if (!duplicateGuard.checkAndRegister(session, url)) {
            allowed = false;
            reason = "duplicate request detected within threshold; activity stopped";
        } else {
            allowed = true;
            reason = "ok";
        }
 
        String json = String.format(
                "{\"allowed\":%s,\"reason\":\"%s\",\"session\":\"%s\"}",
                allowed, escapeJson(reason), escapeJson(session));
 
        byte[] out = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, out.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(out);
        }
    }
 
    private static Map<String, String> parseQuery(String rawQuery) {
        if (rawQuery == null || rawQuery.isBlank()) {
            return Map.of();
        }
        Map<String, String> result = new ConcurrentHashMap<>();
        for (String pair : rawQuery.split("&")) {
            int idx = pair.indexOf('=');
            if (idx < 0) continue;
            String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
            result.put(key, value);
        }
        return result;
    }
 
    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
 
class HealthHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
        byte[] out = "{\"status\":\"ok\",\"service\":\"browserlb-java\"}".getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, out.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(out);
        }
    }
}
 
class BrowserLB {
    public static void main(String[] args) throws IOException {
        int port = 8082;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/api/security/validate", new ValidateHandler());
        server.createContext("/healthz", new HealthHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("BrowserLB Java security service listening on :" + port);
    }
}
 
