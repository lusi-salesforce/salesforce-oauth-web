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
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.function.Supplier;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import okhttp3.FormBody;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public final class SalesforceOAuth {

  private static final HttpUrl CALLBACK_URL = HttpUrl.get("http://localhost:8999/oauth/callback");
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private SalesforceOAuth() {
  }

  public static OkHttpClient authenticate(String clientId, String salesforceDomain) {
    return authenticate(clientId, salesforceDomain, SalesforceOAuth::openBrowser);
  }

  static OkHttpClient authenticate(
      String clientId, String salesforceDomain, Consumer<URI> authorizationPage) {
    var connectedApp = ConnectedApp.from(clientId, salesforceDomain);
    return authenticatedClient(connectedApp, authorizationPage);
  }

  private static String authorize(
      AuthorizationAttempt attempt, Consumer<URI> authorizationPage) {
    try (var callbackServer = new LoopbackCallbackServer(attempt.state)) {
      authorizationPage.accept(attempt.authorizationUrl().uri());
      return callbackServer.awaitAuthorizationCode();
    }
  }

  private static OkHttpClient authenticatedClient(
      ConnectedApp connectedApp, Consumer<URI> authorizationPage) {
    var tokenGateway = new SalesforceTokenGateway(connectedApp);
    Supplier<String> tokenProvider = () -> {
      var attempt = AuthorizationAttempt.forApp(connectedApp);
      var authorizationCode = authorize(attempt, authorizationPage);
      return tokenGateway.exchange(authorizationCode, attempt.pkce());
    };
    return new OkHttpClient.Builder()
        .addInterceptor(new LazyAuthenticationInterceptor(connectedApp.domain(), tokenProvider))
        .build();
  }

  private static final class LazyAuthenticationInterceptor implements Interceptor {

    private final HttpUrl salesforceOrigin;
    private final Supplier<String> tokenProvider;
    private volatile TokenState tokenState = new TokenState(null);

    private LazyAuthenticationInterceptor(
        HttpUrl salesforceOrigin, Supplier<String> tokenProvider) {
      this.salesforceOrigin = salesforceOrigin;
      this.tokenProvider = tokenProvider;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
      var request = chain.request();
      if (!sameOrigin(request.url(), salesforceOrigin)) {
        return chain.proceed(request);
      }

      var requestToken = tokenState;
      if (requestToken.value() == null) {
        requestToken = reauthenticate(requestToken);
      }

      var response = chain.proceed(withAccessToken(request, requestToken.value()));
      if (response.code() == 401) {
        response.close();
        var newToken = reauthenticate(requestToken);
        return chain.proceed(withAccessToken(request, newToken.value()));
      }

      return response;
    }

    private synchronized TokenState reauthenticate(TokenState rejectedToken) {
      // A different request already replaced the snapshot that received the 401.
      if (tokenState != rejectedToken) {
        return tokenState;
      }

      tokenState = new TokenState(tokenProvider.get());
      return tokenState;
    }

    private Request withAccessToken(Request request, String token) {
      return request.newBuilder()
          .header("Authorization", "Bearer " + token)
          .build();
    }

    // Identity tracks refreshes even when Salesforce reissues the same token value after authenticating again
    private record TokenState(String value) {
    }
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

    private SalesforceTokenGateway(ConnectedApp connectedApp) {
      this.connectedApp = connectedApp;
    }

    private String exchange(String authorizationCode, Pkce pkce) {
      if (authorizationCode == null || authorizationCode.isBlank()) {
        throw new SalesforceAuthenticationException(
            "Salesforce authorization callback returned no authorization code");
      }

      var tokenRequest = new FormBody.Builder()
          .add("grant_type", "authorization_code")
          .add("client_id", connectedApp.clientId())
          .add("redirect_uri", CALLBACK_URL.toString())
          .add("code", authorizationCode.trim())
          .add("code_verifier", pkce.verifier())
          .build();
      var request = new Request.Builder()
          .url(connectedApp.tokenEndpoint())
          .post(tokenRequest)
          .build();

      try (var response = httpClient.newCall(request).execute()) {
        var responseContent = response.body().string();
        if (!response.isSuccessful()) {
          throw new SalesforceAuthenticationException(
              "Salesforce token exchange failed: " + responseContent);
        }
        var responseBody = readTokenResponse(responseContent);
        if (!responseBody.has("access_token")) {
          throw new SalesforceAuthenticationException(
              "Salesforce token response has no access_token");
        }
        var accessToken = responseBody.get("access_token").asString();
        if (accessToken == null || accessToken.isBlank()) {
          throw new SalesforceAuthenticationException(
              "Salesforce token response has a blank access_token");
        }
        return accessToken.trim();
      } catch (IOException e) {
        throw new SalesforceAuthenticationException(
            "Could not exchange the Salesforce authorization code: " + e.getMessage());
      }
    }

    private JsonNode readTokenResponse(String responseContent) {
      JsonNode responseBody;
      try {
        responseBody = OBJECT_MAPPER.readTree(responseContent);
      } catch (RuntimeException parsingFailure) {
        throw new SalesforceAuthenticationException(
            "Salesforce token response is not valid JSON");
      }
      if (responseBody == null) {
        throw new SalesforceAuthenticationException(
            "Salesforce token response is empty");
      }
      return responseBody;
    }
  }

  private static final class LoopbackCallbackServer implements AutoCloseable {

    private final String expectedState;
    private final CompletableFuture<String> authorizationCodeFuture = new CompletableFuture<>();
    private final HttpServer server;

    private LoopbackCallbackServer(String expectedState) {
      this.expectedState = expectedState;

      try {
        this.server = HttpServer.create(
            new InetSocketAddress(CALLBACK_URL.host(), CALLBACK_URL.port()),
            0,
            CALLBACK_URL.encodedPath(),
            this::handleSalesforceCallback);
      } catch (IOException e) {
        throw new SalesforceAuthenticationException(
            "Could not start the Salesforce OAuth callback server: " + e.getMessage());
      }
      this.server.start();
    }

    private String awaitAuthorizationCode() {
      try {
        return authorizationCodeFuture.get();
      } catch (InterruptedException failure) {
        Thread.currentThread().interrupt();
        throw new SalesforceAuthenticationException(
            "Salesforce authorization was interrupted");
      } catch (ExecutionException failure) {
        if (failure.getCause() instanceof SalesforceAuthenticationException authenticationFailure) {
          throw authenticationFailure;
        }
        throw new SalesforceAuthenticationException(
            "Salesforce authorization callback failed");
      }
    }

    private void handleSalesforceCallback(HttpExchange exchange) throws IOException {
      var callbackUrl = CALLBACK_URL.newBuilder()
          .encodedQuery(exchange.getRequestURI().getRawQuery())
          .build();
      var state = callbackUrl.queryParameter("state");
      var code = callbackUrl.queryParameter("code");
      if (!constantTimeEquals(expectedState, state == null ? "" : state)) {
        showPageError(exchange, new SalesforceAuthenticationException(
            "Salesforce OAuth callback has an invalid state"));
        return;
      }
      if (code == null || code.isBlank()) {
        var oauthError = callbackUrl.queryParameter("error");
        var description = callbackUrl.queryParameter("error_description");
        showPageError(exchange, new SalesforceAuthenticationException(
            description == null
                ? "Salesforce authorization was rejected"
                : "Salesforce authorization was rejected"
                    + (oauthError == null ? "" : " (" + oauthError + ")")
                    + ": " + description));
        return;
      }
      showPageSuccess(exchange, code);
    }

    private void showPageSuccess(HttpExchange exchange, String code) throws IOException {
      try {
        reply(exchange, 200, "Salesforce authentication complete. You may close this window.");
      } finally {
        authorizationCodeFuture.complete(code);
      }
    }

    private void showPageError(
        HttpExchange exchange, SalesforceAuthenticationException failure) throws IOException {
      try {
        reply(exchange, 400, "Salesforce authentication failed. You may close this window.");
      } finally {
        authorizationCodeFuture.completeExceptionally(failure);
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

  private static boolean sameOrigin(HttpUrl first, HttpUrl second) {
    return first.scheme().equals(second.scheme())
        && first.host().equals(second.host())
        && first.port() == second.port();
  }

  private static String required(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value.trim();
  }

}
