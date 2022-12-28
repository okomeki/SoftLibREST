package net.siisise.json.jws;

import java.security.NoSuchAlgorithmException;
import net.siisise.json.JSON;
import net.siisise.json.JSONValue;

/**
 * 署名とか使えるもの。
 * 署名:HS256 HMAC署名(本人のみ確認可能)
 * 暗号化:なし
 */
public class JWT7519 {

    final JWS7515 jws = new JWS7515();
    
    public JWT7519() {
    }
    
    /**
     * とりあえずHS256用で鍵設定.
     * @param key
     * @throws NoSuchAlgorithmException 
     */
    void init(byte[] key) throws NoSuchAlgorithmException {
        jws.setTyp("JWT");
        jws.setKey(key); // HS256 とりあえず固定
    }

    /**
     * JWS(JWT) でJSONを改行無しで出力し、署名する.
     * あらかじめ鍵の設定が必要。.
     * @param payload
     * @return JWT
     */
    public String sign(JSONValue payload) {
        return jws.compact(payload.toJSON(JSONValue.NOBR));
    }

    /**
     * 
     * @param compact JWT/JWS compact
     * @return payload のJSON
     * @throws SecurityException validateに失敗するなど
     */
    public JSONValue validate(String compact) {
        byte[] payload = jws.validateCompact(compact);
        return JSON.parseWrap(payload);
        
    }
}
