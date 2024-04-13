package net.siisise.json.jose;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import net.siisise.io.BASE64;
import net.siisise.json.JSONObject;
import net.siisise.json.JSONValue;
import net.siisise.security.block.RSAES;
import net.siisise.security.block.RSAES_OAEP;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;

/**
 * 暗号化.
 * AES-GCM など
 * RFC 7516
 * RFC 7159 RFC 8259 Yhe JavaScript Object Notation (JSON) Data Interchange Format
 */
public class JWE7516 {
    private static final Charset UTF8 = StandardCharsets.UTF_8;
    
    private JSONObject jweProtectedHeader;
    private byte[] cek;
    private byte[] jweEncryptedKey;
    private byte[] jweInitializationVector;
    private byte[] jweCiphertext;
    private byte[] jweAuthenticationTag;
    private byte[] jweAAD;
    
    private SecureRandom srnd;
    RSAMiniPrivateKey key;
    RSAPublicKey pub;
    
    public void init(RSAMiniPrivateKey key) {
        try {
            srnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            throw new SecurityException(ex);
        }
        this.key = key;
    }
    
    public void init(RSAPublicKey pub) {
        this.pub = pub;
    }
    
    public String compact(byte[] payload) throws NoSuchAlgorithmException {
        RSAES es = new RSAES_OAEP();
        jweProtectedHeader.put("alg", "RSA-OAEP");
        cek = new byte[16];
        srnd.nextBytes(cek);
        jweEncryptedKey = es.encrypt(pub, cek);
        jweInitializationVector = new byte[16];
        srnd.nextBytes(jweInitializationVector);
        
        StringBuilder jwe = new StringBuilder();
        BASE64 b64 = new BASE64(BASE64.URL,0);
        jwe.append(b64.encode(jweProtectedHeader.toJSON().getBytes(UTF8)));
        jwe.append(".");
        jwe.append(b64.encode(jweEncryptedKey));
        jwe.append(".");
        jwe.append(b64.encode(jweInitializationVector));
        jwe.append(".");
        jwe.append(b64.encode(jweCiphertext));
        jwe.append(".");
        jwe.append(b64.encode(jweAuthenticationTag));
        throw new UnsupportedOperationException();
    }
    
    
    public JSONValue json(byte[] payload) {
        JSONObject json = new JSONObject();
        BASE64 b64 = new BASE64(BASE64.URL,0);
        json.put("protected", b64.encode(jweProtectedHeader.toJSON().getBytes(UTF8)));
        json.put("unprotected", "");
        json.put("header", "");
        json.put("encrypted_key", b64.encode(jweEncryptedKey));
        json.put("iv", b64.encode(jweInitializationVector));
        json.put("ciphertext", b64.encode(jweCiphertext));
        json.put("tag", b64.encode(jweAuthenticationTag));
        json.put("aad", b64.encode(jweAAD));
        throw new UnsupportedOperationException();
    }
    
}
