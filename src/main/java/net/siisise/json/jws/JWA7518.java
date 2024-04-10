package net.siisise.json.jws;

import java.math.BigInteger;
import java.security.MessageDigest;
import net.siisise.io.BASE64;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.json.JSONObject;
import net.siisise.security.digest.SHA256;
import net.siisise.security.digest.SHA384;
import net.siisise.security.digest.SHA512;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;
import net.siisise.security.padding.MGF;
import net.siisise.security.padding.MGF1;
import net.siisise.security.sign.RSASSA_PKCS1_v1_5;
import net.siisise.security.sign.RSASSA_PSS;

/**
 * アルゴリズム
 *
 * https://www.rfc-editor.org/rfc/rfc7518
 */
public abstract class JWA7518 {

    /**
     * MessageDigestとMACが似ているのでまとめる.
     */
    interface DigestAndMAC {

        void init();

        void update(byte[] src);

        byte[] doFinal();

        default byte[] doFinal(byte[] src) {
            update(src);
            return doFinal();
        }

        OBJECTIDENTIFIER oid();
    }

    class MD implements DigestAndMAC {

        final MessageDigest md;
        final OBJECTIDENTIFIER oid;

        MD(MessageDigest md, String oid) {
            this.md = md;
            this.oid = new OBJECTIDENTIFIER(oid);
        }

        @Override
        public void init() {
        }

        @Override
        public void update(byte[] src) {
            md.update(src);
        }

        @Override
        public byte[] doFinal() {
            return md.digest();
        }

        @Override
        public OBJECTIDENTIFIER oid() {
            return oid;
        }
    }

    class DMAC implements DigestAndMAC {

        net.siisise.security.mac.MAC mac;
        OBJECTIDENTIFIER oid;

        DMAC(net.siisise.security.mac.MAC mac, String oid) {
            this.mac = mac;
            this.oid = new OBJECTIDENTIFIER(oid);
        }

        public void init() {
        }

        @Override
        public void update(byte[] src) {
            mac.update(src);
        }

        @Override
        public byte[] doFinal() {
            return mac.sign();
        }

        @Override
        public OBJECTIDENTIFIER oid() {
            return oid;
        }
    }

    public DigestAndMAC alg() {
        throw new UnsupportedOperationException();
    }

    public abstract void update(byte[] src);

    interface SignAlgorithm {

        byte[] sign(JSONObject jwk, byte[] data);

        boolean verify(JSONObject jwk, byte[] data, byte[] sign);
    }

    static MessageDigest toDigest(String alg) {
        String num = alg.substring(2);
        switch (num) {
            case "256":
                return new SHA256();
            case "384":
                return new SHA384();
            case "512":
                return new SHA512();
            default:
                break;
        }
        throw new UnsupportedOperationException();
    }
    
    /**
     * BASE64URL バイナリをBigIntegerにするだけ.
     * 
     * @param s BASE64URLエンコードな数値
     * @return new BigInteger(0x00 + BASE64URLdecode(s))
     */
    private static BigInteger decodeBigHex(String s) {
        BASE64 b64 = new BASE64(BASE64.URL,0);
        byte[] d = b64.decode(s);
        byte[] p = new byte[d.length + 1]; // フラグ消し
        System.arraycopy(d, 0, p, 1, d.length);
        return new BigInteger(p);
    }

    /**
     * 秘密鍵(最小)
     * @param jwk nとd
     * @return 秘密鍵 
     */
    static RSAMiniPrivateKey jwkToRSAPrivate(JSONObject jwk) {
        BigInteger n = decodeBigHex((String)jwk.get("n"));
        BigInteger d = decodeBigHex((String)jwk.get("d"));
        return new RSAMiniPrivateKey(n, d);
    }

    /**
     * 公開鍵
     * @param jwk nとe
     * @return 公開鍵
     */
    static RSAPublicKey jwkToRSAPublic(JSONObject jwk) {
        BigInteger n = decodeBigHex((String)jwk.get("n"));
        BigInteger e = decodeBigHex((String)jwk.get("e"));
        return new RSAPublicKey(n, e);
    }

    static abstract class RSASSA implements SignAlgorithm {

        net.siisise.security.sign.RSASSA ssa;

        @Override
        public byte[] sign(JSONObject jwkPrv, byte[] data) {
            ssa.update(data);
            return ssa.sign(jwkToRSAPrivate(jwkPrv));
        }
        
        @Override
        public boolean verify(JSONObject jwkPub, byte[] data, byte[] sign) {
            
            ssa.update(data);
            return ssa.verify(jwkToRSAPublic(jwkPub), sign);
        }

    }

    static class PKCS1 extends RSASSA {
        
        PKCS1(String alg) {
            ssa = new RSASSA_PKCS1_v1_5(toDigest(alg));
        }
    }

    static class PSS extends RSASSA {

        PSS(String alg) {
            MessageDigest md = toDigest(alg);
            int dl = md.getDigestLength();
            MGF mgf = new MGF1(md);
            ssa = new RSASSA_PSS(toDigest(alg), mgf, dl);
        }
    }

}
