package net.siisise.json.jws;

import java.security.MessageDigest;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;

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
            return mac.doFinal();
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

}
