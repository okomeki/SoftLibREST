package net.siisise.json.jws;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import net.siisise.io.BASE64;
import net.siisise.json.JSONObject;
import net.siisise.security.mac.HMAC;
import net.siisise.json.JSON;
import net.siisise.json.JSONValue;

/**
 * JSON Web Signature (JWS).
 * BASE64URL(UTF8(JWS Protected Header)) || . ||
 * BASE64URL(JWS Payload) || . || BASE64URL(JWS Signature)
 *
 * JWAとJWEも参照.
 * 
 * まだ Compact Headerのみ対応.
 *
 * https://tools.ietf.org/html/rfc7515
 */
public class JWS7515 {

    static final Charset UTF8 = StandardCharsets.UTF_8;
    static final Map<String, String> DIGESTS = new HashMap<>();
    static final Map<String, String> rdigests = new HashMap<>();

    /**
     * RFC 7518 section-3 "alg"
     */
    static {
        DIGESTS.put("HMAC-SHA-256", "HS256"); // Required
        DIGESTS.put("HMAC-SHA-384", "HS384"); // Optional
        DIGESTS.put("HMAC-SHA-512", "HS512"); // Optional
        DIGESTS.put("", "RS256"); // 未
        
        for ( Map.Entry<String, String> es : DIGESTS.entrySet() ) {
            rdigests.put(es.getValue(), es.getKey());
        }
    }

    String jwsCompactHeader = null;

    JSONObject protectedHeader = new JSONObject();
    JSONObject header = new JSONObject();

    SecretKey skey;

    /**
     * 必須のHMAC-SHA-256で鍵にする。
     * @param key
     * @throws NoSuchAlgorithmException 
     */
    public void setKey(byte[] key) throws NoSuchAlgorithmException {
        setKey(new SecretKeySpec(key, "HMAC-SHA-256"));
    }

    /**
     * HMAC鍵の指定。
     * HMAC-SHA-256,384,512が使える。他はまだ未定。
     * @param ks 鍵とHMACアルゴリズムの指定。
     * @throws NoSuchAlgorithmException 
     */
    public void setKey(SecretKey ks) throws NoSuchAlgorithmException {
        skey = ks;
        if ( skey == null ) {
            protectedHeader.put("alg", "none");
        } else {
            String dname = DIGESTS.get(skey.getAlgorithm());
            if (dname == null) {
                throw new NoSuchAlgorithmException(skey.getAlgorithm());
            }
            protectedHeader.put("alg", dname);
        }
        jwsCompactHeader = null;
    }

    /**
     * 種類. optional.
     * とりあえずJWT.
     * JWT
     * JOSE JWS Compact Serialization JWS JWE Compact Serialization
     * JOSE+JSON JWS JSON Serialization, JWE JSON Serialization
     * MIME Media Type (RFC 2046)
     * 
     * @param typ JWT,JOSE mimeも指定可能
     */
    public void setTyp(String typ) {
        protectedHeader.put("typ", typ);
        jwsCompactHeader = null;
    }
    
    /**
     * Content Type ? (OPTIONAL)
     * @param cty ContentType
     */
    public void setCty(String cty) {
        protectedHeader.put("cty", cty);
        jwsCompactHeader = null;
    }

    /**
     * JWSつくるよ?
     * keyとtypを先にセットすること
     *
     * @param payload
     * @return JWS Compact Serialization
     */
    public String compact(String payload) {
        return compact(payload.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 改行なしでJOSE Headerを生成する。
     * アルゴリズムとタイプだけなので固定になりがち
     * 要乱数要素?
     * @return 
     */
    public String compactHeader() {
        if (jwsCompactHeader == null) {
            BASE64 b64 = new BASE64(BASE64.URL, 0);
            jwsCompactHeader = b64.encode(protectedHeader.toJSON(JSONValue.NOBR).getBytes(StandardCharsets.UTF_8));
        }
        return jwsCompactHeader;
    }

    /**
     * JWS Compact Serialization
     * あらかじめ設定したヘッダ、鍵とパラメータのペイロードからJWSを生成.
     * あらかじめkeyとtypの設定が必要.
     * unprotected header は含まない.
     *
     * @param payload
     * @return JWS Compact Serialization (JOSE Header.JWS Payload.JWS Signature
     */
    public String compact(byte[] payload) {
        StringBuilder sb = new StringBuilder();
        JSONObject json = json(payload);

        sb.append(json.get("protected"));
        sb.append(".");
        sb.append(json.get("payload"));
        String signature = (String) json.get("signature");
        if ( signature != null ) {
            // HSxxx
            sb.append(".");
            sb.append(signature);
        }
        return sb.toString();
    }

    private byte[] hmac(SecretKey key, String src) {
        byte[] tmp = src.getBytes(UTF8);
        return new HMAC(key).doFinal(tmp);
    }

    /**
     * JWS JSON Serialization.
     * JSON型のハッシュ計算による署名.
     * まだ HS256 固定
     *
     * @param payload 署名したいデータ
     * @return JWS JSON署名
     */
    public JSONObject json(byte[] payload) {
        BASE64 b64 = new BASE64(BASE64.URL, 0);
        JSONObject jwso = new JSONObject();

        if (!protectedHeader.isEmpty()) {
            jwso.put("protected", compactHeader());
        }
        if ( !header.isEmpty()) {
            jwso.put("header", JSON.copy(header));
        }
        if ( payload != null ) {
            jwso.put("payload", b64.encode(payload));
        }
        String alg = (String) protectedHeader.get("alg");
        if ( skey != null && "HS256".equals(alg)) { // まだ HS256 固定
            String jku; // JWK Set URL (Opt)
            String jwk; // JSON Web Key (Opt)
            HMAC hmac = new HMAC(skey);
            String pro = (String) jwso.get("protected");
            if ( pro != null ) {
                hmac.update(pro.getBytes(StandardCharsets.UTF_8));
//                sb.append(pro);
            }
            hmac.update(new byte[] {'.'});
            String pay = (String) jwso.get("payload");
            if ( pay != null ) {
                hmac.update(pay.getBytes(StandardCharsets.UTF_8));
            }
            jwso.put("signature", b64.encode(hmac.doFinal()));
        } else if ("RS256".equals(alg)) { // まだ
            throw new SecurityException("alg:" + alg);
        } else if (!"none".equals(alg)) {
            throw new SecurityException("alg:" + alg);
        }
        return jwso;
    }

    String jwsSignature() {
        throw new java.lang.UnsupportedOperationException("jwsSignature");
    }

    /**
     * compactHeader() と compact(val) で作ったものの検証.
     * HMACは共通鍵なので発行者用。
     * 
     * かんたんな検証をしてpayloadを取得するだけ.
     * hmac鍵の設定が必要. ヘッダは捨てる.
     *
     * @param jws 全体
     * @return payload
     */
    public byte[] validateCompact(String jws) {
        String[] sp = jws.split("\\.");
        if (sp.length != 3) {
            throw new SecurityException();
        }
        BASE64 b64 = new BASE64(BASE64.URL, 0);
        JSONObject jwsHeader = (JSONObject)JSON.parseWrap(b64.decode(sp[0]));
        if (jwsHeader == null) {
            throw new SecurityException("header parse exception");
        }
        System.out.println(jwsHeader);
        String typ = (String) jwsHeader.get("typ");
        String alg = (String) jwsHeader.get("alg"); // noneとかRSをHSに変える脆弱性があるので要注意
        
        if ( protectedHeader.isEmpty() ) { // HMACはkeyが未設定だといろいろできない
            throw new SecurityException("keyが未設定な exception");
        }
        if (typ == null || !protectedHeader.get("typ").equals(typ)) {
            throw new SecurityException("JWS header typ exception");
        }
        // algが一致することを確認
        if (alg == null || !alg.equals(protectedHeader.get("alg"))) {
            throw new SecurityException(typ + " header alg exception");
        }
        if ( alg.startsWith("HS")) {
            // HS256 HS384 HS512の検証
            //skeyと同じなので作らなくてもいい
//            SecretKey decKey = new SecretKeySpec(skey.getEncoded(), rdigests.get(alg));

            byte[] keyDigest = hmac(skey, sp[0] + "." + sp[1]);
            byte[] jwsDigest = b64.decode(sp[2]);

            // 違うJSONな場合もあるのでheaderは比較しない方がいい
            if (!Arrays.equals(keyDigest, jwsDigest)) {
                throw new SecurityException();
            }
        } else if ( alg.startsWith("RS")) {
            throw new java.lang.UnsupportedOperationException("Unsupported alg:" + alg);
        } else if ( alg.equals("none") ) {
            if ( !sp[2].isEmpty() ) {
                throw new SecurityException();
            }    
        } else {
            throw new SecurityException("unknown alg:" + alg);
        }
        return b64.decode(sp[1]);
    }
    
    /**
     * エラー足りないかも.
     * @param jws
     * @return 
     */
    public JSONValue header(String jws) {
        validateCompact(jws);
        String[] sp = jws.split("\\.");
        if (sp.length != 3) {
            throw new SecurityException();
        }
        BASE64 b64 = new BASE64(BASE64.URL, 0);
        return JSON.parseWrap(b64.decode(sp[0]));
    }

    public byte[] payload(String jws) {
        return validateCompact(jws);
    }

    /**
     * header と payload をjson にしてみる
     * @param jws
     * @return 
     */
    public static JSONObject clientAll(String jws) {
        BASE64 burl = new BASE64(BASE64.URL,0);
        String[] sp = jws.split("\\.");
        JSONObject o = new JSONObject();
        byte[] header = burl.decode(sp[0]);
        byte[] payload = burl.decode(sp[1]);
        JSONValue head = JSON.parseWrap(header);
        o.putJSON("header", head);
        o.putJSON("payload", JSON.parseWrap(payload));
        return o;
    }
}
