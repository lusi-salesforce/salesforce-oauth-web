package pl.lusicloud.salesforceoauthweb;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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
  void authenticatesBeforeTheFirstRequestAndReauthenticatesWhenUnauthorized() throws Exception {
    AtomicInteger authorizationCount = new AtomicInteger();
    AtomicInteger tokenCount = new AtomicInteger();
    AtomicInteger requestCount = new AtomicInteger();
    List<String> authorizationHeaders = new ArrayList<>();
    List<String> tokenRequests = new ArrayList<>();
    HttpServer fakeSalesforce = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    fakeSalesforce.createContext("/services/oauth2/token", exchange -> {
      int tokenNumber = tokenCount.incrementAndGet();
      tokenRequests.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      var rotatedRefreshToken = tokenNumber < 3
          ? ",\"refresh_token\":\"test-refresh-token-" + tokenNumber + "\""
          : "";
      respond(exchange, 200, "{\"access_token\":\"test-access-token-" + tokenNumber + "\""
          + rotatedRefreshToken + "}");
    });
    fakeSalesforce.createContext("/services/data", exchange -> {
      authorizationHeaders.add(exchange.getRequestHeaders().getFirst("Authorization"));
      int requestNumber = requestCount.incrementAndGet();
      respond(exchange, requestNumber == 2 || requestNumber == 4 ? 401 : 200, "ok");
    });
    fakeSalesforce.start();

    try {
      String domain = "http://localhost:" + fakeSalesforce.getAddress().getPort();
      OkHttpClient client = SalesforceOAuth.authenticate("test-client-id", domain, authorizationUri -> {
        authorizationCount.incrementAndGet();
        assertEquals("test-client-id", queryValue(authorizationUri, "client_id"));
        assertEquals("S256", queryValue(authorizationUri, "code_challenge_method"));
        assertEquals("api refresh_token", queryValue(authorizationUri, "scope"));
        assertEquals("http://localhost:8999/oauth/callback", queryValue(authorizationUri, "redirect_uri"));
        String callback = "http://localhost:8999/oauth/callback?code=test-code&state="
            + queryValue(authorizationUri, "state");
        try (HttpClient anotherClient = HttpClient.newHttpClient()) {
          anotherClient.send(HttpRequest.newBuilder(URI.create(callback)).GET().build(), HttpResponse.BodyHandlers.discarding());
        } catch (IOException | InterruptedException failure) {
          throw new RuntimeException(failure);
        }
      });
      assertEquals(0, authorizationCount.get());
      assertEquals(0, tokenCount.get());

      try (Response response = client.newCall(new Request.Builder().url(domain + "/services/data").build()).execute()) {
        assertTrue(response.isSuccessful());
      }
      try (Response response = client.newCall(new Request.Builder().url(domain + "/services/data").build()).execute()) {
        assertTrue(response.isSuccessful());
      }
      try (Response response = client.newCall(new Request.Builder().url(domain + "/services/data").build()).execute()) {
        assertTrue(response.isSuccessful());
      }

      assertEquals(1, authorizationCount.get());
      assertEquals(3, tokenCount.get());
      assertEquals(List.of(
          "Bearer test-access-token-1",
          "Bearer test-access-token-1",
          "Bearer test-access-token-2",
          "Bearer test-access-token-2",
          "Bearer test-access-token-3"), authorizationHeaders);
      assertTrue(tokenRequests.get(0).contains("grant_type=authorization_code"));
      assertTrue(tokenRequests.get(1).contains("grant_type=refresh_token"));
      assertTrue(tokenRequests.get(1).contains("refresh_token=test-refresh-token-1"));
      assertTrue(tokenRequests.get(2).contains("refresh_token=test-refresh-token-2"));
    } finally {
      fakeSalesforce.stop(0);
    }
  }

  @Test
  void doesNotAuthenticateOrSendTheTokenToAnotherOrigin() throws Exception {
    AtomicInteger authorizationCount = new AtomicInteger();
    AtomicReference<String> foreignAuthorizationHeader = new AtomicReference<>();
    HttpServer fakeSalesforce = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    fakeSalesforce.createContext("/services/oauth2/token", exchange ->
        respond(exchange, 200,
            "{\"access_token\":\"test-access-token\",\"refresh_token\":\"test-refresh-token\"}"));
    fakeSalesforce.createContext("/services/data", exchange -> respond(
        exchange,
        exchange.getRequestHeaders().getFirst("Authorization") == null ? 401 : 200,
        "ok"));
    fakeSalesforce.start();

    HttpServer foreignServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    foreignServer.createContext("/foreign", exchange -> {
      foreignAuthorizationHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
      respond(exchange, 401, "unauthorized");
    });
    foreignServer.start();

    try {
      String domain = "http://localhost:" + fakeSalesforce.getAddress().getPort();
      OkHttpClient client = SalesforceOAuth.authenticate("test-client-id", domain, authorizationUri -> {
        authorizationCount.incrementAndGet();
        completeAuthorization(authorizationUri);
      });

      try (Response response = client.newCall(
          new Request.Builder().url(domain + "/services/data").build()).execute()) {
        assertTrue(response.isSuccessful());
      }

      String foreignUrl = "http://localhost:" + foreignServer.getAddress().getPort() + "/foreign";
      try (Response response = client.newCall(
          new Request.Builder().url(foreignUrl).build()).execute()) {
        assertEquals(401, response.code());
      }

      assertNull(foreignAuthorizationHeader.get());
      assertEquals(1, authorizationCount.get());
    } finally {
      foreignServer.stop(0);
      fakeSalesforce.stop(0);
    }
  }

  @Test
  void coalescesConcurrentAuthenticationAttempts() throws Exception {
    int requestCount = 4;
    AtomicInteger authorizationCount = new AtomicInteger();
    AtomicInteger tokenCount = new AtomicInteger();
    CountDownLatch ready = new CountDownLatch(requestCount);
    CountDownLatch start = new CountDownLatch(1);
    HttpServer fakeSalesforce = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    fakeSalesforce.createContext("/services/oauth2/token", exchange -> {
      tokenCount.incrementAndGet();
      respond(exchange, 200,
          "{\"access_token\":\"test-access-token\",\"refresh_token\":\"test-refresh-token\"}");
    });
    fakeSalesforce.createContext("/services/data", exchange -> {
      respond(
          exchange,
          exchange.getRequestHeaders().getFirst("Authorization") == null ? 500 : 200,
          "ok");
    });

    try (var serverExecutor = Executors.newCachedThreadPool();
        var clientExecutor = Executors.newFixedThreadPool(requestCount)) {
      fakeSalesforce.setExecutor(serverExecutor);
      fakeSalesforce.start();
      String domain = "http://localhost:" + fakeSalesforce.getAddress().getPort();
      OkHttpClient client = SalesforceOAuth.authenticate("test-client-id", domain, authorizationUri -> {
        authorizationCount.incrementAndGet();
        completeAuthorization(authorizationUri);
      });

      var calls = java.util.stream.IntStream.range(0, requestCount)
          .mapToObj(ignored -> clientExecutor.submit(() -> {
            ready.countDown();
            start.await();
            try (Response response = client.newCall(
                new Request.Builder().url(domain + "/services/data").build()).execute()) {
              assertTrue(response.isSuccessful());
            }
            return null;
          }))
          .toList();
      assertTrue(ready.await(5, TimeUnit.SECONDS));
      start.countDown();
      for (var call : calls) {
        call.get(10, TimeUnit.SECONDS);
      }

      assertEquals(1, authorizationCount.get());
      assertEquals(1, tokenCount.get());
    } finally {
      fakeSalesforce.stop(0);
    }
  }

  @Test
  void exposesTokenExchangeFailure() throws Exception {
    HttpServer fakeSalesforce = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    fakeSalesforce.createContext("/services/oauth2/token", exchange -> respond(
        exchange,
        400,
        "{\"error\":\"invalid_grant\",\"error_description\":\"Authorization code expired\"}"));
    fakeSalesforce.createContext("/services/data", exchange ->
        respond(exchange, 401, "unauthorized"));
    fakeSalesforce.start();

    try {
      String domain = "http://localhost:" + fakeSalesforce.getAddress().getPort();
      OkHttpClient client = SalesforceOAuth.authenticate(
          "test-client-id", domain, SalesforceOauthWebApplicationTests::completeAuthorization);

      SalesforceAuthenticationException failure = assertThrows(
          SalesforceAuthenticationException.class,
          () -> client.newCall(
              new Request.Builder().url(domain + "/services/data").build()).execute());

      assertEquals(
          "Salesforce token exchange failed: "
              + "{\"error\":\"invalid_grant\",\"error_description\":\"Authorization code expired\"}",
          failure.getMessage());
    } finally {
      fakeSalesforce.stop(0);
    }
  }

  @Test
  void reauthorizesWhenTheRefreshTokenIsRejected() throws Exception {
    AtomicInteger authorizationCount = new AtomicInteger();
    AtomicInteger tokenRequestCount = new AtomicInteger();
    AtomicInteger businessRequestCount = new AtomicInteger();
    List<String> tokenRequests = new ArrayList<>();
    HttpServer fakeSalesforce = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    fakeSalesforce.createContext("/services/oauth2/token", exchange -> {
      int requestNumber = tokenRequestCount.incrementAndGet();
      tokenRequests.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      if (requestNumber == 2) {
        respond(exchange, 400, "{\"error\":\"invalid_grant\"}");
        return;
      }
      respond(exchange, 200, "{\"access_token\":\"test-access-token-" + requestNumber
          + "\",\"refresh_token\":\"test-refresh-token-" + requestNumber + "\"}");
    });
    fakeSalesforce.createContext("/services/data", exchange -> {
      int requestNumber = businessRequestCount.incrementAndGet();
      respond(exchange, requestNumber == 2 ? 401 : 200, "ok");
    });
    fakeSalesforce.start();

    try {
      String domain = "http://localhost:" + fakeSalesforce.getAddress().getPort();
      OkHttpClient client = SalesforceOAuth.authenticate("test-client-id", domain, authorizationUri -> {
        authorizationCount.incrementAndGet();
        completeAuthorization(authorizationUri);
      });

      try (Response response = client.newCall(
          new Request.Builder().url(domain + "/services/data").build()).execute()) {
        assertTrue(response.isSuccessful());
      }
      try (Response response = client.newCall(
          new Request.Builder().url(domain + "/services/data").build()).execute()) {
        assertTrue(response.isSuccessful());
      }

      assertEquals(2, authorizationCount.get());
      assertEquals(3, tokenRequestCount.get());
      assertTrue(tokenRequests.get(0).contains("grant_type=authorization_code"));
      assertTrue(tokenRequests.get(1).contains("grant_type=refresh_token"));
      assertTrue(tokenRequests.get(2).contains("grant_type=authorization_code"));
    } finally {
      fakeSalesforce.stop(0);
    }
  }

  private static String queryValue(URI uri, String name) {
    return Objects.requireNonNull(HttpUrl.get(uri)).queryParameter(name);
  }

  private static void completeAuthorization(URI authorizationUri) {
    String callback = "http://localhost:8999/oauth/callback?code=test-code&state="
        + queryValue(authorizationUri, "state");
    try (HttpClient anotherClient = HttpClient.newHttpClient()) {
      anotherClient.send(
          HttpRequest.newBuilder(URI.create(callback)).GET().build(),
          HttpResponse.BodyHandlers.discarding());
    } catch (IOException | InterruptedException failure) {
      throw new RuntimeException(failure);
    }
  }

  private static void respond(HttpExchange exchange, int status, String content) throws IOException {
    byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length);
    try (var response = exchange.getResponseBody()) {
      response.write(bytes);
    }
  }
}
