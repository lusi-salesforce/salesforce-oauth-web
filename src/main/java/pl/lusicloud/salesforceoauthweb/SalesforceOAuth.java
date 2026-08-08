package pl.lusicloud.salesforceoauthweb;

import java.awt.Desktop;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import okhttp3.FormBody;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public final class SalesforceOAuth {

  private static final HttpUrl CALLBACK_URL = HttpUrl.get("http://localhost:8999/oauth/callback");

  private SalesforceOAuth() {
  }

  public static OkHttpClient authenticate(String clientId, String salesforceDomain) {
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
      authorizationPage.accept(attempt.authorizationUrl().uri());
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
    System.out.println("Trying to open this URL in a browser to authenticate with Salesforce:\n" + authorizationUri);
    if (Desktop.isDesktopSupported()) {
      try {
        Desktop.getDesktop().browse(authorizationUri);
      } catch (IOException ignored) {
        // The printed URL is the fallback for headless or restricted environments.
      }
    }
  }

  private record ConnectedApp(String clientId, HttpUrl domain) {

    private static ConnectedApp from(String clientId, String domain) {
      var configuredDomain = required(domain, "salesforceDomain");
      var origin = HttpUrl.get(configuredDomain.contains("://")
          ? configuredDomain
          : "https://" + configuredDomain);
      var hasInvalidParts = !origin.username().isEmpty()
          || !origin.password().isEmpty()
          || origin.query() != null
          || origin.fragment() != null
          || !"/".equals(origin.encodedPath());
      if (hasInvalidParts) {
        throw new IllegalArgumentException("salesforceDomain must be a host name or origin URL");
      }

      var isLocalHttp = "http".equals(origin.scheme())
          && ("localhost".equals(origin.host()) || "127.0.0.1".equals(origin.host()));
      if (!origin.isHttps() && !isLocalHttp) {
        throw new IllegalArgumentException("salesforceDomain must use HTTPS");
      }

      return new ConnectedApp(required(clientId, "clientId"), origin);
    }

    private HttpUrl authorizationUrl(String state, Pkce pkce) {
      return endpoint("services/oauth2/authorize")
          .addQueryParameter("response_type", "code")
          .addQueryParameter("client_id", clientId)
          .addQueryParameter("redirect_uri", CALLBACK_URL.toString())
          .addQueryParameter("state", state)
          .addQueryParameter("scope", "api")
          .addQueryParameter("code_challenge", pkce.challenge())
          .addQueryParameter("code_challenge_method", "S256")
          .build();
    }

    private HttpUrl tokenEndpoint() {
      return endpoint("services/oauth2/token").build();
    }

    private HttpUrl.Builder endpoint(String path) {
      return domain.newBuilder().addPathSegments(path);
    }
  }

  private record AuthorizationAttempt(String state, Pkce pkce, HttpUrl authorizationUrl) {

    private static AuthorizationAttempt forApp(ConnectedApp connectedApp) {
      var state = UUID.randomUUID().toString();
      var pkce = Pkce.create();
      return new AuthorizationAttempt(state, pkce, connectedApp.authorizationUrl(state, pkce));
    }
  }

  private record Pkce(String verifier, String challenge) {

    private static Pkce create() {
      var verifier = UUID.randomUUID() + "." + UUID.randomUUID();
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

    private String exchange(String authorizationCode, Pkce pkce) {
      var tokenRequest = new FormBody.Builder()
          .add("grant_type", "authorization_code")
          .add("client_id", connectedApp.clientId())
          .add("redirect_uri", CALLBACK_URL.toString())
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
            new InetSocketAddress(CALLBACK_URL.host(), CALLBACK_URL.port()), 0);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
      this.server.createContext(CALLBACK_URL.encodedPath(), this::receive);
      this.server.start();
    }

    private String awaitAuthorizationCode() {
      try {
        return authorizationCode.get();
      } catch (Exception failure) {
        throw new RuntimeException("Salesforce authorization failed", failure.getCause());
      }
    }

    private void receive(HttpExchange exchange) throws IOException {
      var callbackUrl = CALLBACK_URL.newBuilder()
          .encodedQuery(exchange.getRequestURI().getRawQuery())
          .build();
      var state = callbackUrl.queryParameter("state");
      var code = callbackUrl.queryParameter("code");
      if (!constantTimeEquals(expectedState, state == null ? "" : state) || code == null) {
        reject(exchange, callbackUrl.queryParameter("error_description"));
        return;
      }
      accept(exchange, code);
    }

    private void accept(HttpExchange exchange, String code) throws IOException {
      try {
        reply(exchange, 200, "Salesforce authentication complete. You may close this window.");
      } finally {
        authorizationCode.complete(code);
      }
    }

    private void reject(HttpExchange exchange, String errorDescription) throws IOException {
      try {
        reply(exchange, 400, "Salesforce authentication failed. You may close this window.");
      } finally {
        authorizationCode.completeExceptionally(new IOException(
            errorDescription == null ? "Invalid Salesforce OAuth callback" : errorDescription));
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

}
