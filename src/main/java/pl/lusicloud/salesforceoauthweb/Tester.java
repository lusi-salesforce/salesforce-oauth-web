package pl.lusicloud.salesforceoauthweb;

import java.io.IOException;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class Tester {
  static void main() throws IOException {
    var clientId = "put client id here";
    var salesforceDomain = "https://changeme.my.salesforce.com";
    OkHttpClient client = SalesforceOAuth.authenticate(clientId, salesforceDomain);

    Request request = new Request.Builder().url("https://changeme.my.salesforce.com/services/data/v66.0/limits")
        .get().build();

    try (Response res = client.newCall(request).execute()) {
      System.out.println("res.body().string() = " + res.body().string());
    }
  }
}
