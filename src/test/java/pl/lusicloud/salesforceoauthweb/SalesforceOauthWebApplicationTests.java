package pl.lusicloud.salesforceoauthweb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import org.junit.jupiter.api.Test;

class SalesforceOauthWebApplicationTests {

  @Test
  void authenticatesTemporarilyAndReturnsAuthenticatedClient() throws Exception {
    AtomicReference<String> authorizationHeader = new AtomicReference<>();
    HttpServer fakeSalesforce = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    fakeSalesforce.createContext("/services/oauth2/token", exchange -> respond(exchange, 200, "{\"access_token\":\"test-access-token\"}"));
    fakeSalesforce.createContext("/services/data", exchange -> {
      authorizationHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
      respond(exchange, 200, "ok");
    });
    fakeSalesforce.start();

    try {
      String domain = "http://localhost:" + fakeSalesforce.getAddress().getPort();
      OkHttpClient client = SalesforceOAuth.authenticate("test-client-id", domain, authorizationUri -> {
        assertEquals("test-client-id", queryValue(authorizationUri, "client_id"));
        assertEquals("S256", queryValue(authorizationUri, "code_challenge_method"));
        assertEquals("http://localhost:8999/oauth/callback", queryValue(authorizationUri, "redirect_uri"));
        String callback = "http://localhost:8999/oauth/callback?code=test-code&state="
            + queryValue(authorizationUri, "state");
        try (HttpClient anotherClient = HttpClient.newHttpClient()) {
          anotherClient.send(HttpRequest.newBuilder(URI.create(callback)).GET().build(), HttpResponse.BodyHandlers.discarding());
        } catch (IOException | InterruptedException failure) {
          throw new RuntimeException(failure);
        }
      });

      try (Response response = client.newCall(new Request.Builder().url(domain + "/services/data").build()).execute()) {
        assertTrue(response.isSuccessful());
      }
      assertEquals("Bearer test-access-token", authorizationHeader.get());
    } finally {
      fakeSalesforce.stop(0);
    }
  }

  private static String queryValue(URI uri, String name) {
    return Objects.requireNonNull(HttpUrl.get(uri)).queryParameter(name);
  }

  private static void respond(HttpExchange exchange, int status, String content) throws IOException {
    byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length);
    try (var response = exchange.getResponseBody()) {
      response.write(bytes);
    }
  }
}
