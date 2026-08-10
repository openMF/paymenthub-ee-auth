package org.apache.fineract.config;

import org.springframework.core.io.ClassPathResource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Loads the RSA key pair (jwt.pem / jwt_pub.pem) used to sign and verify the
 * OAuth JWTs. The old Spring Security OAuth2 stack parsed these PEM files
 * itself (spring-security-jwt); that library is gone in Spring Security 6, so
 * this small helper does the same job with plain JDK classes.
 *
 * jwt.pem is in the legacy PKCS#1 format ("BEGIN RSA PRIVATE KEY"), which the
 * JDK KeyFactory cannot read directly - it is wrapped into a PKCS#8 envelope
 * in memory (no key file changes needed).
 */
public final class PemUtils {

    private PemUtils() {
    }

    /**
     * The PEM file as it is on disk. Used by /oauth/token_key, which published
     * the verifier key in this exact form in the old stack.
     */
    public static String readPublicKeyPem(String classpathFile) {
        try {
            return readPem(classpathFile).trim();
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read " + classpathFile, e);
        }
    }

    public static RSAPublicKey readPublicKey(String classpathFile) {
        try {
            byte[] der = readPemBody(classpathFile);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read RSA public key from " + classpathFile, e);
        }
    }

    public static RSAPrivateKey readPrivateKey(String classpathFile) {
        try {
            String pem = readPem(classpathFile);
            byte[] der = decodeBody(pem);
            if (pem.contains("BEGIN RSA PRIVATE KEY")) {
                // PKCS#1 -> wrap into a PKCS#8 PrivateKeyInfo structure
                der = wrapPkcs1InPkcs8(der);
            }
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read RSA private key from " + classpathFile, e);
        }
    }

    private static String readPem(String classpathFile) throws IOException {
        return new String(new ClassPathResource(classpathFile).getInputStream().readAllBytes(), StandardCharsets.US_ASCII);
    }

    private static byte[] readPemBody(String classpathFile) throws IOException {
        return decodeBody(readPem(classpathFile));
    }

    private static byte[] decodeBody(String pem) {
        String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    /**
     * PKCS#8 = SEQUENCE { INTEGER 0, SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING <pkcs#1 bytes> }
     */
    private static byte[] wrapPkcs1InPkcs8(byte[] pkcs1) throws IOException {
        byte[] version = { 0x02, 0x01, 0x00 };
        byte[] rsaAlgorithmIdentifier = {
                0x30, 0x0d, // SEQUENCE, 13 bytes
                0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID 1.2.840.113549.1.1.1
                0x05, 0x00 // NULL
        };
        byte[] octetString = der(0x04, pkcs1);

        ByteArrayOutputStream content = new ByteArrayOutputStream();
        content.write(version);
        content.write(rsaAlgorithmIdentifier);
        content.write(octetString);
        return der(0x30, content.toByteArray());
    }

    /** One DER TLV: tag + length (short or long form) + content. */
    private static byte[] der(int tag, byte[] content) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int len = content.length;
        if (len < 0x80) {
            out.write(len);
        } else {
            int numBytes = (32 - Integer.numberOfLeadingZeros(len) + 7) / 8;
            out.write(0x80 | numBytes);
            for (int i = numBytes - 1; i >= 0; i--) {
                out.write((len >> (8 * i)) & 0xff);
            }
        }
        out.write(content);
        return out.toByteArray();
    }
}
