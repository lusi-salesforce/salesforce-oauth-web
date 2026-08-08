package pl.lusicloud.salesforceoauthweb;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.util.Objects;

import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class Tester {
  private static final String ENV_VAR_CLIENT_ID = "SALESFORCE_CLIENT_ID";
  private static final String ENV_VAR_DOMAIN = "SALESFORCE_DOMAIN";
  private static final String ENV_VAR_API_VERSION = "SALESFORCE_API_VERSION";

  private static final String DEFAULT_CLIENT_ID = "your default client id here";
  private static final String DEFAULT_DOMAIN = "https://change-me-or-use-env-variables.my.salesforce.com/";
  private static final String DEFAULT_API_VERSION = "v66.0";

  static void main() throws IOException {
    var clientId = System.getenv().getOrDefault(ENV_VAR_CLIENT_ID, DEFAULT_CLIENT_ID);
    var salesforceDomain = System.getenv().getOrDefault(ENV_VAR_DOMAIN, DEFAULT_DOMAIN);
    var apiVersion = System.getenv().getOrDefault(ENV_VAR_API_VERSION, DEFAULT_API_VERSION);
    OkHttpClient client = SalesforceOAuth.authenticate(clientId, salesforceDomain);

    HttpUrl urlLimits = requireNonNull(HttpUrl.parse(salesforceDomain)).newBuilder().addPathSegments("/services/data/" + apiVersion + "/limits").build();
    Request requestLimits = new Request.Builder().url(urlLimits).get().build();

    try (Response res = client.newCall(requestLimits).execute()) {
      System.out.println("res.body().string() = " + res.body().string());
    }
  }
}
