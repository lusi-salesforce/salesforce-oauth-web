package pl.lusicloud.salesforceoauthweb;

import java.awt.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

final class SalesforceOAuth {

  static final URI CALLBACK_URI = URI.create("http://localhost:8999/oauth/callback");
  private static final SecureRandom RANDOM = new SecureRandom();

  private SalesforceOAuth() {
  }

  static OkHttpClient authenticate(String clientId, String salesforceDomain) {
    return authenticate(clientId, salesforceDomain, SalesforceOAuth::openBrowser);
  }

  static OkHttpClient authenticate(
      String clientId, String salesforceDomain, Consumer<URI> authorizationPage) {
    var connectedApp = ConnectedApp.from(clientId, salesforceDomain);
    var attempt = AuthorizationAttempt.forApp(connectedApp);
    var authorizationCode = authorize(attempt, authorizationPage);
    var accessToken = new SalesforceTokenGateway(connectedApp)
        .exchange(authorizationCode, attempt.pkce());
    return authenticatedClient(accessToken);
  }

  private static String authorize(
      AuthorizationAttempt attempt, Consumer<URI> authorizationPage) {
    try (var callbackServer = new LoopbackCallbackServer(attempt.state)) {
      authorizationPage.accept(attempt.authorizationUri());
      return callbackServer.awaitAuthorizationCode();
    }
  }

  private static OkHttpClient authenticatedClient(String accessToken) {
    return new OkHttpClient.Builder()
        .addInterceptor(chain -> chain.proceed(chain.request().newBuilder()
            .header("Authorization", "Bearer " + accessToken)
            .build()))
        .build();
  }

  private static void openBrowser(URI authorizationUri) {
    System.out.println("Open this URL to authenticate with Salesforce:\n" + authorizationUri);
    if (Desktop.isDesktopSupported()) {
      try {
        Desktop.getDesktop().browse(authorizationUri);
      } catch (IOException ignored) {
        // The printed URL is the fallback for headless or restricted environments.
      }
    }
  }

  private record ConnectedApp(String clientId, URI domain) {

    static ConnectedApp from(String clientId, String domain) {
      var configuredDomain = required(domain, "salesforceDomain");
      var origin = URI.create(configuredDomain.contains("://")
          ? configuredDomain
          : "https://" + configuredDomain);
      var hasInvalidParts = origin.getHost() == null
          || origin.getUserInfo() != null
          || origin.getQuery() != null
          || origin.getFragment() != null
          || origin.getPath() != null && !origin.getPath().isBlank() && !"/".equals(origin.getPath());
      if (hasInvalidParts) {
        throw new IllegalArgumentException("salesforceDomain must be a host name or origin URL");
      }

      var isLocalHttp = "http".equalsIgnoreCase(origin.getScheme())
          && ("localhost".equalsIgnoreCase(origin.getHost()) || "127.0.0.1".equals(origin.getHost()));
      if (!"https".equalsIgnoreCase(origin.getScheme()) && !isLocalHttp) {
        throw new IllegalArgumentException("salesforceDomain must use HTTPS");
      }

      var normalizedOrigin = URI.create(origin.getScheme() + "://" + origin.getRawAuthority());
      return new ConnectedApp(required(clientId, "clientId"), normalizedOrigin);
    }

    URI authorizationUri(String state, Pkce pkce) {
      return URI.create(endpoint("/services/oauth2/authorize") + "?"
          + "response_type=code"
          + "&client_id=" + encode(clientId)
          + "&redirect_uri=" + encode(CALLBACK_URI.toString())
          + "&state=" + encode(state)
          + "&scope=api"
          + "&code_challenge=" + encode(pkce.challenge())
          + "&code_challenge_method=S256");
    }

    String tokenEndpoint() {
      return endpoint("/services/oauth2/token");
    }

    String endpoint(String path) {
      return domain + path;
    }
  }

  private record AuthorizationAttempt(String state, Pkce pkce, URI authorizationUri) {

    static AuthorizationAttempt forApp(ConnectedApp connectedApp) {
      var state = randomUrlSafe(32);
      var pkce = Pkce.create();
      return new AuthorizationAttempt(state, pkce, connectedApp.authorizationUri(state, pkce));
    }
  }

  private record Pkce(String verifier, String challenge) {

    static Pkce create() {
      var verifier = randomUrlSafe(64);
      return new Pkce(verifier, sha256UrlSafe(verifier));
    }
  }

  private static final class SalesforceTokenGateway {

    private final ConnectedApp connectedApp;
    private final OkHttpClient httpClient = new OkHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private SalesforceTokenGateway(ConnectedApp connectedApp) {
      this.connectedApp = connectedApp;
    }

    String exchange(String authorizationCode, Pkce pkce) {
      var tokenRequest = new FormBody.Builder()
          .add("grant_type", "authorization_code")
          .add("client_id", connectedApp.clientId())
          .add("redirect_uri", CALLBACK_URI.toString())
          .add("code", required(authorizationCode, "authorizationCode"))
          .add("code_verifier", pkce.verifier())
          .build();
      var request = new Request.Builder()
          .url(connectedApp.tokenEndpoint())
          .post(tokenRequest)
          .build();

      try (var response = httpClient.newCall(request).execute()) {
        var responseBody = objectMapper.readTree(response.body().string());
        if (!response.isSuccessful()) {
          throw tokenExchangeFailure(response, responseBody);
        }
        if (!responseBody.has("access_token")) {
          throw new IOException("Salesforce token response has no access_token");
        }
        return required(responseBody.get("access_token").asString(), "accessToken");
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    private IOException tokenExchangeFailure(Response response, JsonNode responseBody) {
      var reason = responseBody.has("error_description")
          ? responseBody.get("error_description").asString()
          : Integer.toString(response.code());
      return new IOException("Salesforce token exchange failed: " + reason);
    }
  }

  private static final class LoopbackCallbackServer implements AutoCloseable {

    private final String expectedState;
    private final CompletableFuture<String> authorizationCode = new CompletableFuture<>();
    private final HttpServer server;

    private LoopbackCallbackServer(String expectedState) {
      this.expectedState = expectedState;

      try {
        this.server = HttpServer.create(
            new InetSocketAddress("localhost", CALLBACK_URI.getPort()), 0);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
      this.server.createContext(CALLBACK_URI.getPath(), this::receive);
      this.server.start();
    }

    String awaitAuthorizationCode() {
      try {
        return authorizationCode.get();
      } catch (Exception failure) {
        throw new RuntimeException("Salesforce authorization failed", failure.getCause());
      }
    }

    private void receive(HttpExchange exchange) throws IOException {
      var callbackParameters = query(exchange.getRequestURI().getRawQuery());
      if (!constantTimeEquals(expectedState, callbackParameters.getOrDefault("state", ""))
          || !callbackParameters.containsKey("code")) {
        reject(exchange, callbackParameters);
        return;
      }
      accept(exchange, callbackParameters.get("code"));
    }

    private void accept(HttpExchange exchange, String code) throws IOException {
      try {
        reply(exchange, 200, "Salesforce authentication complete. You may close this window.");
      } finally {
        authorizationCode.complete(code);
      }
    }

    private void reject(HttpExchange exchange, Map<String, String> callbackParameters)
        throws IOException {
      try {
        reply(exchange, 400, "Salesforce authentication failed. You may close this window.");
      } finally {
        authorizationCode.completeExceptionally(new IOException(
            callbackParameters.getOrDefault(
                "error_description", "Invalid Salesforce OAuth callback")));
      }
    }

    @Override
    public void close() {
      server.stop(0);
    }
  }

  private static void reply(HttpExchange exchange, int status, String message) throws IOException {
    var body = message.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
    exchange.sendResponseHeaders(status, body.length);
    try (var response = exchange.getResponseBody()) {
      response.write(body);
    }
  }

  private static Map<String, String> query(String rawQuery) {
    var values = new HashMap<String, String>();
    if (rawQuery == null || rawQuery.isBlank()) {
      return values;
    }
    for (var parameter : rawQuery.split("&")) {
      var pair = parameter.split("=", 2);
      values.put(decode(pair[0]), pair.length == 2 ? decode(pair[1]) : "");
    }
    return values;
  }

  private static String randomUrlSafe(int bytes) {
    var value = new byte[bytes];
    RANDOM.nextBytes(value);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
  }

  private static String sha256UrlSafe(String value) {
    try {
      var digest = MessageDigest.getInstance("SHA-256")
          .digest(value.getBytes(StandardCharsets.US_ASCII));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException(impossible);
    }
  }

  private static boolean constantTimeEquals(String expected, String actual) {
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8),
        actual.getBytes(StandardCharsets.UTF_8));
  }

  private static String required(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value.trim();
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private static String decode(String value) {
    return URLDecoder.decode(value, StandardCharsets.UTF_8);
  }
}
