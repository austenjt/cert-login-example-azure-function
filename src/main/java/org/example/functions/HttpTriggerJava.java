package org.example.functions;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.*;

import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.microsoft.azure.functions.annotation.*;
import com.microsoft.azure.functions.*;
import okhttp3.OkHttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class HttpTriggerJava {

    // CERT has been uploaded to function app certificate storage
    private static final String CERT_PASS = System.getenv("SIC_CERT_PASS");
    private static final String CERT_TYPE = "PKCS12"; // .pfx/.p12

    // Azure login creds, if needed
    private static final String AZURE_CLIENT_ID = System.getenv("AZURE_CLIENT_ID");
    private static final String AZURE_CLIENT_SECRET = System.getenv("AZURE_CLIENT_SECRET");
    private static final String AZURE_TENANT_ID = System.getenv("AZURE_TENANT_ID");

    /**
     * Instructions:
     *   * create a Microsoft Entra ID App Registration
     *     * Authentication: Single tenant AD
     *     * Get client ID in OVerview
     *     * Create secret key in Certificates & Secrets
     *   * Create a key vault
     *     * IAM settings might not matter if you are Administrator
     *     * Import the certificate
     *     * Create an Access Policy:  a) use Key, Secret, & Cert Management template
     *         b) for the Principal , select your App Registration (!!! NOT YOUR USER ACCOUNT !!!)
     *         c) on the Application tab, nothing needs to be selected (DON'T FORGET THIS!!)
     */
    @FunctionName("load")
    public HttpResponseMessage loadCert(
        @HttpTrigger(name = "load", methods = {HttpMethod.GET},
            authLevel = AuthorizationLevel.ANONYMOUS) HttpRequestMessage<Optional<String>> request,
        final ExecutionContext context) {
        context.getLogger().info("Java HTTP trigger processed a request.");
        try {


            String hexData = "";
            //String hexData = downloadSecretAsHex();
            //String hexData = downloadCertificateAsHex();
            hexData = downloadCertFromFunctionApp();

            return request.createResponseBuilder(HttpStatus.ACCEPTED)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "*")
                .header("Access-Control-Allow-Headers", "Content-Type")
                .body("Loaded Cert: \n" + hexData)
                .build();
        } catch (Exception e) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "*")
                .header("Access-Control-Allow-Headers", "Content-Type")
                .body("Exception encountered while trying to load the cert: \n" + e.getMessage())
                .build();
        }
    }




    public static String downloadCertFromFunctionApp() {
        final DefaultAzureCredential azureCredential = new DefaultAzureCredentialBuilder()
            .build();


        return "";
    }

    public static String downloadSecretAsHex() {
        final DefaultAzureCredential azureCredential = new DefaultAzureCredentialBuilder()
            .build();
        SecretClient secretClient = new SecretClientBuilder()
            .vaultUrl("https://jonausten-kv-test.vault.azure.net")
            .credential(azureCredential)
            .buildClient();

        String secretName = "secretnopass";
        KeyVaultSecret secret = secretClient.getSecret(secretName);
        String secretValue = secret.getValue();
        System.out.println("\nSecret value:\n" + secretValue);
        return bytesToHex(secretValue.getBytes(StandardCharsets.UTF_8));
    }

    public static String downloadCertificateAsHex() {

        final DefaultAzureCredential azureCredential = new DefaultAzureCredentialBuilder()
            .build();
        CertificateClient certificateClient = new CertificateClientBuilder()
            .vaultUrl("https://jonausten-kv-test.vault.azure.net")
            .credential(azureCredential)
            .buildClient();
        String secretName = "test";
        KeyVaultCertificateWithPolicy certificate = certificateClient.getCertificate(secretName);
        byte[] secretValue = certificate.getCer();
        System.out.println("\nSecret value:\n" + Arrays.toString(secretValue));
        return bytesToHex(secretValue);
    }

    public static void testInitializeSSL(String hexData) {
        try (ByteArrayInputStream fis = new ByteArrayInputStream(hexData.getBytes(StandardCharsets.UTF_8))) {
            final KeyStore keyStore = KeyStore.getInstance(CERT_TYPE);
            keyStore.load(fis, CERT_PASS.toCharArray());

            final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance
                (TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            final TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

            if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
                throw new IllegalStateException("Unexpected default trust managers: " + Arrays.toString(trustManagers));
            }

            final X509TrustManager trustManager = (X509TrustManager) trustManagers[0];
            final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("PKIX");
            keyManagerFactory.init(keyStore, CERT_PASS.toCharArray());

            final SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            new OkHttpClient().newBuilder()
                .connectTimeout(Duration.ofMillis(30000L))
                .readTimeout(Duration.ofMillis(10000L))
                .callTimeout(Duration.ofMillis(30000L))
                .writeTimeout(Duration.ofMillis(30000L))
                .sslSocketFactory(sslSocketFactory, trustManager)
                .build();
        } catch (IOException | IllegalStateException | KeyManagementException | KeyStoreException |
                 NoSuchAlgorithmException | UnrecoverableKeyException | CertificateException e) {
            System.err.printf("Error loading trusted certificate for client. %s%n", e.getMessage());
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        final int bytesPerLine = 16;
        final int charInterval = 4;

        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % bytesPerLine == 0) {
                hexString.append("\n");
            } else if (i > 0 && (i * 2) % charInterval == 0) {
                hexString.append(" ");
            }

            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    @FunctionName("hello")
    public HttpResponseMessage runHello(
        @HttpTrigger(name = "hello", methods = {HttpMethod.GET, HttpMethod.POST},
            authLevel = AuthorizationLevel.ANONYMOUS) HttpRequestMessage<Optional<String>> request,
        final ExecutionContext context) {
        context.getLogger().info("Java HTTP trigger processed a request.");

        String query = request.getQueryParameters().get("name");
        String name = request.getBody().orElse(query);

        if (name == null) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "*")
                .header("Access-Control-Allow-Headers", "Content-Type")
                .body("Please pass a name parameter on the query string or in the request body.")
                .build();
        } else {
            return request.createResponseBuilder(HttpStatus.ACCEPTED)
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "*")
                .header("Access-Control-Allow-Headers", "Content-Type")
                .body("Hello, " + name)
                .build();
        }
    }


}
