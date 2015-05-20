/*
 * Java Payloads trust manager loader class for Metasploit.
 * 
 * Copyright (c) 2011, Michael 'mihi' Schierl
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *   
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *   
 * - Neither name of the copyright holders nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *   
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND THE CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR THE CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.metasploit.stage;

import java.net.URLConnection;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Trust manager used for HTTPS stagers. This is in its own class because it
 * depends on classes only present on Sun JRE 1.4+, and incorporating it into
 * the main {@link Payload} class would have made it impossible for other/older
 * JREs to load it.
 */
public class PayloadTrustManager implements X509TrustManager, HostnameVerifier {

    public X509Certificate[] getAcceptedIssuers() {
        // no preferred issuers
        return new X509Certificate[0];
    }

    public static String getCertificateSHA1(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(cert.getEncoded());
        return bytesToHex(md.digest());
    }

    public static String bytesToHex(byte bytes[]) {
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        for (byte aByte : bytes) {
            buf.append(hexDigits[(aByte & 0xf0) >> 4]);
            buf.append(hexDigits[aByte & 0x0f]);
        }
        return buf.toString();
    }

    public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
                                   String authType) {
        // trust everyone
    }

    public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
                                   String authType) throws CertificateException {

        String payloadHash = Payload.CERT_HASH.substring(4).trim();
        if (payloadHash.length() == 0) {
            // No HandlerSSLCert set on payload, trust everyone
            return;
        }
        if (certs == null || certs.length < 1) {
            throw new CertificateException();
        }
        for (X509Certificate certificate : certs) {
            try {
                String serverHash = getCertificateSHA1(certificate);
                if (!serverHash.equals(payloadHash)) {
                    throw new CertificateException("Invalid certificate");
                }
            } catch (Exception e) {
                throw new CertificateException(e);
            }
        }
    }

    public boolean verify(String hostname, SSLSession session) {
        // trust everyone
        return true;
    }

    /**
     * Called by the {@link Payload} class to modify the given
     * {@link URLConnection} so that it uses this trust manager.
     */
    public static void useFor(URLConnection uc) throws Exception {
        if (uc instanceof HttpsURLConnection) {
            HttpsURLConnection huc = ((HttpsURLConnection) uc);
            PayloadTrustManager ptm = new PayloadTrustManager();
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, new TrustManager[]{ptm},
                    new java.security.SecureRandom());
            huc.setSSLSocketFactory(sc.getSocketFactory());
            huc.setHostnameVerifier(ptm);
        }
    }
}
