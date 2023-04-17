package net.siisise.json.jws;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import net.siisise.io.BASE64;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.json.JSONObject;
import net.siisise.security.mac.HMAC;
import net.siisise.json.JSON;
import net.siisise.json.JSONArray;
import net.siisise.json.JSONValue;
import net.siisise.security.block.RSA;
import net.siisise.security.digest.SHA256;
import net.siisise.security.digest.SHA384;
import net.siisise.security.digest.SHA512;
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

    private String jwsCompactHeader = null;

    private JSONObject protectedHeader = new JSONObject();
    private JSONObject header = new JSONObject();
    
    private SecretKey skey;

    private Set<String> algorithms;
    private JSONArray rsakeyList;

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
     * 公開鍵リスト (検証用)
     * @param keys jwks
     */
    public void setRsaPublic(JSONArray keys) {
        rsakeyList = keys;
        JSONObject key = (JSONObject)keys.get(0);
        String alg = (String)key.get("alg"); // とりあえず
        protectedHeader.put("alg", alg);
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
    
    private RSAMiniPrivateKey jwkToRSAPrivate(JSONObject jwk) {
        BigInteger n = decodeBigHex((String)jwk.get("n"));
        BigInteger d = decodeBigHex((String)jwk.get("d"));
        return new RSAMiniPrivateKey(n, d);
    }

    private RSAPublicKey jwkToRSAPublic(JSONObject jwk) {
        BigInteger n = decodeBigHex((String)jwk.get("n"));
        BigInteger e = decodeBigHex((String)jwk.get("e"));
        return new RSAPublicKey(n, e);
    }

    /**
     * 
     * @param asn
     * @return 
     */
    private byte[] rsaSign(byte[] asn) {
        String kid = (String) protectedHeader.get("kid");
        JSONObject jwk = selectKey(kid); // 秘密鍵を指しておいて
        
        RSAMiniPrivateKey pkey = jwkToRSAPrivate(jwk);
        String nkey = (String)jwk.get("n");
        // padding
        int nlen = nkey.length() * 3 / 4;
        byte[] pad = new byte[nlen];
        int len = pad.length - asn.length;
        pad[1] = 1;
        for (int i = 2; i < len - 1; i++ ) {
            pad[i] = (byte)0xff;
        }
        System.arraycopy(asn, 0, pad, len, asn.length);
        BigInteger bi = RSA.os2ip(pad);
        BigInteger r = pkey.rsasp1(bi);
        return RSA.i2osp(r, nlen);
    }
    
    private byte[] decodeRsa(byte[] sign, JSONObject key) {
        BigInteger di = new BigInteger(sign);
        
        RSAPublicKey pub = jwkToRSAPublic(key);
        String nkey = (String)key.get("n");
        BigInteger r = pub.rsavp1(di); // 署名検証
        
        byte[] dec = r.toByteArray(); // 1バイト短い予定
        if ( dec.length + 1 != nkey.length() * 3 / 4 || dec[0] != 1) {
            throw new SecurityException();
        }
        int i = 1;
        while ((dec[i] & 0xff) == 0xff) {
         i++;
        }
        if (i == 1 || dec[i++] != 0) {
            throw new SecurityException();
        }
        byte[] src = new byte[dec.length - i];
        System.arraycopy(dec,i,src,0,dec.length - i);
        return src;
    }

    /**
     * BASE64URL バイナリをBigIntegerにするだけ.
     * 
     * @param s BASE64URLエンコードな数値
     * @return new BigInteger(0x00 + BASE64URLdecode(s))
     */
    private BigInteger decodeBigHex(String s) {
        BASE64 b64 = new BASE64(BASE64.URL,0);
        byte[] d = b64.decode(s);
        byte[] p = new byte[d.length + 1]; // フラグ消し
        System.arraycopy(d, 0, p, 1, d.length);
        return new BigInteger(p);
    }
    
    /**
     * JWS JSON Serialization.
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
        if ( !header.isEmpty()) {
            jwso.put("header", JSON.copy(header));
        }
        if ( payload != null ) {
            jwso.put("payload", b64.encode(payload));
        }
        String alg = (String) protectedHeader.get("alg");
        if ( skey != null && "HS256".equals(alg) || "HS384".equals(alg) || "HS512".equals(alg)) {
            HMAC hmac = new HMAC(skey);
            String pro = (String) jwso.get("protected");
            if ( pro != null ) {
                hmac.update(pro.getBytes(StandardCharsets.UTF_8));
            }
            hmac.update(new byte[] {'.'});
            String pay = (String) jwso.get("payload");
            if ( pay != null ) {
                hmac.update(pay.getBytes(StandardCharsets.UTF_8));
            }
            jwso.put("signature", b64.encode(hmac.doFinal()));
        } else if ("RS256".equals(alg) || "RS384".equals(alg) || "RS512".equals(alg)) {
            String[] sp = new String[2];
            sp[0] = (String) jwso.get("protected");
            sp[1] = (String) jwso.get("payload");
            byte[] asn = digestRS(sp,alg);
            jwso.put("signature", b64.encode(rsaSign(asn)));
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
            validateRS(sp, jwsHeader);
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
     * ハッシュとASN.1ヘッダ
     * @param sp ヘッダとpayload
     * @param alg
     * @return ASN.1型ハッシュ
     */
    byte[] digestRS(String[] sp, String alg) {
        MessageDigest md;
        String oid;

        switch (alg) {
            case "RS256":
                md = new SHA256();
                oid = SHA256.OBJECTIDENTIFIER;
                break;
            case "RS384":
                md = new SHA384();
                oid = SHA384.OBJECTIDENTIFIER;
                break;
            case "RS512":
                md = new SHA512();
                oid = SHA512.OBJECTIDENTIFIER;
                break;
            default:
                throw new UnsupportedOperationException("Unsupported alg:" + alg);
        }
        byte[] keyDigest = md.digest((sp[0] + "." + sp[1]).getBytes(UTF8));
        SEQUENCE rsa = new SEQUENCE();
        SEQUENCE algt = new SEQUENCE();
        algt.add(new OBJECTIDENTIFIER(oid));
        algt.add(new NULL());
        rsa.add(algt);
        OCTETSTRING os = new OCTETSTRING(keyDigest);
        rsa.add(os);
        return rsa.encodeAll();
    }
    
    void validateRS(String[] sp, JSONObject jwsHeader) {
        String alg = (String)jwsHeader.get("alg");
        byte[] encDigest = digestRS(sp,alg); // ASN.1ヘッダ付き

        JSONObject jwk = selectKey((String)jwsHeader.get("kid"));
        BASE64 b64 = new BASE64(BASE64.URL, 0);
        byte[] jwsDigest = decodeRsa(b64.decode(sp[2]),jwk); // ASN.1型
        
        if (!Arrays.equals(encDigest, jwsDigest)) {
            for ( int i = 0; i < jwsDigest.length; i++ ) {
                String h = "0" + Integer.toHexString(jwsDigest[i] & 0xff);
                System.out.print(h.substring(h.length() - 2));
            }
            System.out.println();
            for ( int i = 0; i < encDigest.length; i++ ) {
                String h = "0" + Integer.toHexString(encDigest[i] & 0xff);
                System.out.print(h.substring(h.length() - 2));
            }
            System.out.println();
            throw new SecurityException("" + encDigest.length + " " + jwsDigest.length);
        }
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
