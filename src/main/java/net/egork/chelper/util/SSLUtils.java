package net.egork.chelper.util;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;

import javax.net.ssl.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * This class provide various static methods that relax X509 certificate and
 * hostname verification while using the SSL over the HTTP protocol.
 *
 * @author Francis Labrie
 */
public final class SSLUtils {
    /**
     * Hostname verifier.
     */
    private static HostnameVerifier _hostnameVerifier;
    /**
     * Thrust managers.
     */
    private static TrustManager[] _trustManagers;

    /**
     * Return true if the protocol handler property java.
     * protocol.handler.pkgs is set to the Sun's com.sun.net.ssl.
     * internal.www.protocol deprecated one, false
     * otherwise.
     *
     * @return true if the protocol handler
     * property is set to the Sun's deprecated one, false
     * otherwise.
     */
    private static boolean isDeprecatedSSLProtocol() {
        return ("com.sun.net.ssl.internal.www.protocol".equals(System.
                getProperty("java.protocol.handler.pkgs")));
    } // isDeprecatedSSLProtocol

    /**
     * Set the default Hostname Verifier to an instance of a fake class that
     * trust all hostnames.
     */
    private static void _trustAllHostnames() {
        // Install the all-trusting host name verifier:
        if (_hostnameVerifier == null) {
            _hostnameVerifier = new DefaultHostnameVerifier();
        }
        HttpsURLConnection.setDefaultHostnameVerifier(_hostnameVerifier);
    } // _trustAllHttpsCertificates

    /**
     * Set the default X509 Trust Manager to an instance of a fake class that
     * trust all certificates, even the self-signed ones.
     */
    private static void _trustAllHttpsCertificates() {
        SSLContext context;

        // Create a trust manager that does not validate certificate chains
        if (_trustManagers == null) {
            _trustManagers = new TrustManager[]{new FakeX509TrustManager()};
        } // if
        // Install the all-trusting trust manager:
        try {
            context = SSLContext.getInstance("SSL");
            context.init(null, _trustManagers, new SecureRandom());
        } catch (GeneralSecurityException gse) {
            throw new IllegalStateException(gse.getMessage());
        } // catch
        HttpsURLConnection.setDefaultSSLSocketFactory(context.
                getSocketFactory());
    } // _trustAllHttpsCertificates

    /**
     * Set the default Hostname Verifier to an instance of a fake class that
     * trust all hostnames.
     */
    public static void trustAllHostnames() {
        _trustAllHostnames();
    } // trustAllHostnames

    /**
     * Set the default X509 Trust Manager to an instance of a fake class that
     * trust all certificates, even the self-signed ones.
     */
    public static void trustAllHttpsCertificates() {
        _trustAllHttpsCertificates();
    } // trustAllHttpsCertificates

    /**
     * This class allow any X509 certificates to be used to authenticate the
     * remote side of a secure socket, including self-signed certificates.
     *
     * @author Francis Labrie
     */
    public static class FakeX509TrustManager implements X509TrustManager {

        /**
         * Empty array of certificate authority certificates.
         */
        private static final X509Certificate[] _AcceptedIssuers =
                new X509Certificate[]{};


        /**
         * Always trust for client SSL chain peer certificate
         * chain with any authType authentication types.
         *
         * @param chain    the peer certificate chain.
         * @param authType the authentication type based on the client
         *                 certificate.
         */
        @Override
        public void checkClientTrusted(X509Certificate[] chain,
                                       String authType) {
        } // checkClientTrusted

        /**
         * Always trust for server SSL chain peer certificate
         * chain with any authType exchange algorithm types.
         *
         * @param chain    the peer certificate chain.
         * @param authType the key exchange algorithm used.
         */
        @Override
        public void checkServerTrusted(X509Certificate[] chain,
                                       String authType) {
        } // checkServerTrusted

        /**
         * Return an empty array of certificate authority certificates which
         * are trusted for authenticating peers.
         *
         * @return a empty array of issuer certificates.
         */
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return (_AcceptedIssuers);
        } // getAcceptedIssuers
    } // FakeX509TrustManager
} // SSLUtilities