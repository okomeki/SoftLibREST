package net.siisise.json.jws;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import net.siisise.io.BASE64;
import net.siisise.json.JSONObject;
import net.siisise.security.mac.HMAC;
import net.siisise.json.JSON;
import net.siisise.json.JSONArray;
import net.siisise.json.JSONValue;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;

/**
 * JSON Web Signature (JWS).
 * データ列をBASE64URLっぽくして署名/検証する.
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
//    static final Map<String, String> rdigests = new HashMap<>();

    /**
     * RFC 7518 section-3 "alg"
     */
    static {
        DIGESTS.put("HMAC-SHA-256", "HS256"); // Required
        DIGESTS.put("HMAC-SHA-384", "HS384"); // Optional
        DIGESTS.put("HMAC-SHA-512", "HS512"); // Optional
//        DIGESTS.put("", "RS256"); // 未
        
//        for ( Map.Entry<String, String> es : DIGESTS.entrySet() ) {
//            rdigests.put(es.getValue(), es.getKey());
//        }
    }

    private String jwsCompactHeader = null;

    private JSONObject protectedHeader = new JSONObject();
    private JSONObject header = new JSONObject();
    
    /**
     * HMAC鍵.
     */
    private SecretKey skey;

    private Set<String> algorithms;
    private JSONArray rsakeyList;
    
    public JWS7515() {
        protectedHeader.put("alg", "none");
    }

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
     * RSA秘密鍵 (署名用)
     * @param kid 鍵ID
     * @param alg RS256 など
     * @param pkey RSA秘密鍵
     */
    public void setRsaKey(String kid, String alg, RSAMiniPrivateKey pkey) {
        setRsaKey(kid, alg, rsaPrivateToJwk(pkey));
    }

    /**
     * RSA公開鍵 (検証用).
     * テスト鍵っぽいもの
     * @param kid kid
     * @param alg アルゴリズム RS256など
     * @param key RSA公開鍵
     */
    public void setRsaKey(String kid, String alg, RSAPublicKey key) {
        setRsaKey(kid, alg, rsaPublicToJwk(key));
    }

    /**
     * RSA鍵 (署名用/検証用)
     * @param kid 鍵ID
     * @param alg RS256 など
     * @param key 鍵
     */
    public void setRsaKey(String kid, String alg, JSONObject key) {
        if ( rsakeyList == null ) {
            rsakeyList = new JSONArray();
        }
        if ( key == null ) {
            setAlg("none");
        } else {
            setAlg(alg);
            setKid(kid);
            rsakeyList.putJSON(kid, key);
        }
        jwsCompactHeader = null;
    }
    
    /**
     * RSA鍵の選択 (署名用)
     * @param kid 
     */
    public void setKid(String kid) {
        protectedHeader.put("kid", kid);
    }
    
    public void setAlg(String alg) {
        protectedHeader.put("alg", alg);
    }
    
    public String getKid() {
        return (String) protectedHeader.get("kid");
    }

    public String getAlg() {
        return (String) protectedHeader.get("alg");
    }

    /**
     * RSA公開鍵リスト (検証用)
     * @param keys jwks
     */
    public void setRsaPublic(JSONArray keys) {
        rsakeyList = keys;
        JSONObject key = (JSONObject)keys.get(0);
        String alg = (String)key.get("alg"); // とりあえず
//        String kid = (String)key.get("kid");
        setAlg(alg);
//        protectedHeader.put("kid", kid);
    }

    /**
     * 種類. optional.
     * とりあえずJWT 署名.
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
            jwsCompactHeader = b64.encode(((String)protectedHeader.rebind(JSONValue.NOBR)).getBytes(StandardCharsets.UTF_8));
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
    
    private JSONObject rsaPrivateToJwk(RSAMiniPrivateKey key) {
        JSONObject jwk = new JSONObject();
        String n = encodeBigHex(key.getModulus());
        String d = encodeBigHex( key.getPrivateExponent() );
        jwk.put("n", n);
        jwk.put("d", d);
        return jwk;
    }

    private JSONObject rsaPublicToJwk(RSAPublicKey key) {
        JSONObject jwk = new JSONObject();
        String n = encodeBigHex(key.getModulus());
        String e = encodeBigHex( key.getPublicExponent());
        jwk.put("n", n);
        jwk.put("e", e);
        return jwk;
    }

    /**
     * RSASSA_PKCS1_v1_5 sign
     * RSASSA-PSS
     * @param data
     * @return 
     */
    private byte[] rsassaSign(byte[] data) {
        String alg = getAlg(); //(String) protectedHeader.get("alg");
        String kid = getKid();
        JWA7518.RSASSA ssa = toRSASSA(alg);
        JSONObject jwk = selectKey(kid); // 秘密鍵を指しておいて
        return ssa.sign(jwk, data);
    }

    private JWA7518.RSASSA toRSASSA(String alg) {
        if ( alg.startsWith("RS")) {
            return new JWA7518.PKCS1(alg);
        } else if ( alg.startsWith("PS")) {
            return new JWA7518.PSS(alg);
        }
        throw new UnsupportedOperationException();
    }

    byte[] hmacSign(byte[] s) {
        HMAC hmac = new HMAC(skey);
        hmac.update(s);
        return hmac.sign();
    }

    void validateHS(String[] sp) {
        BASE64 b64 = new BASE64(BASE64.URL, 0);
            // HS256 HS384 HS512の検証
        HMAC hmac = new HMAC(skey);
        hmac.update((sp[0] + "." + sp[1]).getBytes(UTF8));

        // 違うJSONな場合もあるのでheaderは比較しない方がいい
        if (!hmac.verify(b64.decode(sp[2]))) {
            throw new SecurityException();
        }
    }

    /**
     * RSASSA-PKCS1-v1_5 using SHA-XXX または
     * RSASSA-PSS using SHA-XXX and MGF1 with SHA-XXX 検証.
     * @param sp
     * @param jwsHeader alg, kid
     */
    void validateRSASSA(String[] sp, JSONObject jwsHeader) {
        String alg = (String)jwsHeader.get("alg");
        BASE64 b64 = new BASE64(BASE64.URL, 0);
        byte[] m = (sp[0] + "." + sp[1]).getBytes(UTF8);
        byte[] s = b64.decode(sp[2]);
        JSONObject jwk = selectKey((String)jwsHeader.get("kid"));

        JWA7518.RSASSA ssa = toRSASSA(alg);
        if (!ssa.verify(jwk, m,s)) {
            throw new SecurityException();
        }
    }
    
    /**
     * 
     * @param n
     * @return 
     */
    private String encodeBigHex(BigInteger n) {
        byte[] d = n.toByteArray();
        if (d[0] == 0) {
            byte[] p = new byte[d.length - 1];
            System.arraycopy(d, 1, p, 0, p.length);
            d = p;
        }
        BASE64 b64 = new BASE64(BASE64.URL, 0);
        return b64.encode(d);
    }
    
    /**
     * JSON型のハッシュ計算による署名.
     * HSとRSたぶん
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
        if (!header.isEmpty()) {
            jwso.put("header", JSON.copy(header));
        }
        if (payload != null) {
            jwso.put("payload", b64.encode(payload));
        }
        String alg = (String) protectedHeader.get("alg");
        String[] sp = new String[2];
        sp[0] = (String)jwso.get("protected");
        if ( sp[0] == null ) {
            sp[0] = "";
        }
        sp[1] = (String)jwso.get("payload");
        if ( sp[1] == null ) {
            sp[1] = "";
        }
        byte[] s = (sp[0] + "." + sp[1]).getBytes(StandardCharsets.UTF_8);
        if ( skey != null && "HS256".equals(alg) || "HS384".equals(alg) || "HS512".equals(alg)) {
            jwso.put("signature", b64.encode(hmacSign(s)));
        } else if ("RS256".equals(alg) || "RS384".equals(alg) || "RS512".equals(alg) ||
                   "PS256".equals(alg) || "PS384".equals(alg) || "PS512".equals(alg)) {
            jwso.put("signature", b64.encode(rsassaSign(s)));
        } else if (!"none".equals(alg)) {
            throw new SecurityException("alg:" + alg);
        }
        return jwso;
    }

    /**
     * compactHeader() と compact(val) で作ったものの検証.
     * HMACは共通鍵なので発行者用。
     * 
     * RFC 7518 Section 3?
     * 
     * かんたんな検証をしてpayloadを取得するだけ.
     * hmacまたはrsa鍵の設定が必要. ヘッダは捨てる.
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
        String typ = (String) jwsHeader.get("typ");
        String alg = (String) jwsHeader.get("alg"); // noneとかRSをHSに変える脆弱性があるので要注意
        
        if ( protectedHeader.isEmpty() ) { // HMACはkeyが未設定だといろいろできない
            throw new SecurityException("keyが未設定な exception");
        }
        if (typ == null || !protectedHeader.get("typ").equals(typ)) {
            throw new SecurityException("JWS header typ exception　:" + typ);
        }
        // algが一致することを確認
        if (alg == null || !alg.equals(protectedHeader.get("alg"))) {
            throw new SecurityException(typ + " header alg exception");
        }
        if ( alg.startsWith("HS")) {
            validateHS(sp);
        } else if ( alg.startsWith("RS") || alg.startsWith("PS")) {
            validateRSASSA(sp, jwsHeader);
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
            throw new SecurityException("形式不明");
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

    private JSONObject selectKey(String kid) {
        for ( Object k : rsakeyList ) {
            JSONObject key = (JSONObject)k;
            if ( kid.equals(key.get("kid"))) {
                return key;
            }
        }
        throw new SecurityException("鍵なし");
    }
}
