/*
 * Copyright 2022 okome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.siisise.oauth.client;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.siisise.io.BASE64;
import net.siisise.json.JSONArray;
import net.siisise.json.JSONObject;
import net.siisise.json.jws.JWT7519;
import net.siisise.net.http.HttpServer;
import net.siisise.rest.RestClient;
import net.siisise.rest.RestException;
import net.siisise.security.digest.SHA256;

/**
 * OAuthのClient としていろいろ使える準備.
 * RFC 6749
 * RFC 7636
 */
public class OAuthClient extends RestClient {

    public static final String GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"; // RFC 7523
    public static final String CLIENT_ASSERTION_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public static final String OOB = "urn:ietf:wg:oauth:2.0:oob";

    private AccessInfo access;
    private final ClientInfo info;

    private String redirect;
    private String state;
    private String nonce;
    private String code_verifier;
    private HttpServer httpd;

    /**
     * サーバに登録されたClient ID, Client Secret を知っている状態からスタート.
     * @param info client 情報
     */
    public OAuthClient(ClientInfo info) {
        super("", null);
        this.info = info;
        redirect = "http://127.0,0.1:9099/oauth-web-client/authd"; // 仮
    }
    
    public void setRedirect(String uri) {
        redirect = uri;
    }

    public ClientInfo info() {
        return info;
    }

    /**
     * 認可コードフロー.
     * callback から token 取得まで行う.
     * @param cb method,query など
     * @return 
     */
    public String authCb(JSONObject cb) {
//        String method = (String)cb.get("method");
        Map<String,String> query = (Map)cb.get("query");
        String code = query.get("code");
        JSONObject exr = new JSONObject();
        exr.put("all", cb);

        if ( code == null || !state.equals(query.get("state")) ) {
            return new JSONObject().toJSON();
        }
        try {
            JSONObject ac = authcode(code);
            exr.putJSON("ac",ac);
            String idToken = (String)ac.get("id_token");
            JWT7519 jwt = new JWT7519();
            JSONArray algs = info.idTokenSigningAlgValuesSupported();
            jwt.init(info.keys());
            exr.putJSON("payload", jwt.validate(idToken));
            return exr.toJSON();
        } catch (IOException ex) {
            Logger.getLogger(OAuthClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (URISyntaxException ex) {
            Logger.getLogger(OAuthClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (RestException ex) {
            Logger.getLogger(OAuthClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return exr.toJSON();
    }

    /**
     * Auth サーバ用.
     * response_type code
     * リダイレクト先がある場合
     * @param redirect_uri
     * @param scope
     * @return auth link
     * @throws java.io.IOException callbackサーバ作れなかった
     * @throws java.security.NoSuchAlgorithmException
     */
    public URI authLink(URI redirect_uri, String scope) throws IOException, NoSuchAlgorithmException {
        redirect = redirect_uri.toASCIIString();
        return createSecureAuth("code", scope);
    }
    
    /**
     * Authorization Code
     * ローカルサーバ用
     * response_type code
     * @param redirect_uri redirect URI
     * @param callback
     * @param scope
     * @return auth link
     * @throws NoSuchAlgorithmException
     * @throws IOException 
     */
    public URI authLink(URI redirect_uri, Function<JSONObject,Object> callback, String scope) throws NoSuchAlgorithmException, IOException {
        redirect = callbackLocalServer(redirect_uri, callback);
        return createSecureAuth("code", scope);
    }
    
    /**
     * JavaScript等で処理できればいいかもしれない
     * @param cb
     * @return 
     */
    JSONObject implicitCb(JSONObject cb) {
        return cb;
    }

    /**
     * implicit.
     * JavaScript 等用
     * # でqueryが返るのでサーバで受けられない
     * @param redirect_uri redirect URI
     * @param scope
     * @return auth link
     * @throws NoSuchAlgorithmException
     * @throws IOException 
     */
    public URI implicitLink(URI redirect_uri, String scope) throws NoSuchAlgorithmException, IOException {
        redirect = callbackLocalServer(redirect_uri, this::implicitCb);
        return createSecureAuth("token", scope);
    }

    /**
     * client_id, redirect_uri, state, nonce をつけて auth へ
     * @param params
     * @return
     * @throws NoSuchAlgorithmException 
     */
    URI createSecureAuth(String response_type, String scope) throws NoSuchAlgorithmException {
        JSONObject params = new JSONObject();
        params.put("response_type", response_type);
        params.put("client_id", info.clientId());
        params.put("redirect_uri", this.redirect);
        if ( scope != null ) {
            params.put("scope", scope);
        }
        SecureRandom sr = SecureRandom.getInstanceStrong();
        BASE64 b64 = new BASE64(BASE64.URL,0);
        byte[] rnd = new byte[8];
        sr.nextBytes(rnd);
        state = b64.encode(rnd); // 仮
        params.put("state", state);
        sr.nextBytes(rnd);
        nonce = b64.encode(rnd); // 今まで使われていない値
        params.put("nonce", nonce);
        
        JSONArray methods = info.codeChallengeMethodsSupported();
        if ( methods != null && methods.contains("S256")) {
            // RFC 7636 PKCE
            rnd = new byte[45];
            sr.nextBytes(rnd);
            code_verifier = b64.encode(rnd); // 43 - 128文字
            SHA256 s256 = new SHA256();
            String code_challenge = b64.encode(s256.digest(code_verifier.getBytes(StandardCharsets.UTF_8))); // ASCII文字としてHASH
            params.put("code_challenge", code_challenge);
            params.put("code_challenge_method", "S256");
        }
        
        return param(info.authuri(), params);
    }

    /**
     * httpd 受け付け専用のhttpdを立ててみる無謀な計画.
     * @return redirect url
     */
    String callbackLocalServer(URI redirect_uri, Function<JSONObject,Object> callback) throws IOException {
        close();
        httpd = new HttpServer();
        httpd.callback(callback);
        httpd.callback(redirect_uri.getPath(), callback);
        int port = redirect_uri.getPort();
        String scheme = redirect_uri.getScheme();
        if ( port == -1 ) {
            if ( "http".equals(scheme)) {
                port = 80;
            } else {
                throw new java.net.UnknownServiceException();
            }
        }
        InetAddress loopback = InetAddress.getLoopbackAddress();
        httpd.start(loopback, port);
        
        return redirect_uri.toASCIIString();
    }
    
    public void close() throws IOException {
        if ( httpd != null ) {
            httpd.close();
            httpd = null;
        }
    }

    /**
     * token 1回目.
     * client id, client secretが必要
     * access token, refresh token を取得する.
     * @param code
     * @return
     * @throws java.io.IOException
     * @throws java.net.URISyntaxException
     * @throws net.siisise.rest.RestException 
     */
    public JSONObject authcode(String code) throws IOException, URISyntaxException, RestException {
        // client id と client secret BASIC認証
        JSONObject params = new JSONObject();
        params.put("grant_type", "authorization_code");
        params.put("code",code);
        params.put("redirect_uri", redirect);
//        params.put("client_id",info.clientId());
//        params.put("client_secret", info.secret());
        params.put("code_verifier", code_verifier);
        return token(params);
    }

    /**
     * refresh token をつかう
     * @return 
     * @throws net.siisise.rest.RestException 
     * @throws java.io.IOException 
     * @throws java.net.URISyntaxException 
     */
    public JSONObject refresh() throws RestException, IOException, URISyntaxException {
        JSONObject params = new JSONObject();
        params.put("grant_type", "refresh_token"); // "client_credentials"
//        params.put("client_id",info.clientId());
//        params.put("client_secret", info.secret());
        params.put("refresh_toekn", access.refreshToken);
        params.put("redirect_uri", redirect);
//        params.put("code_verifier", code_verifier); // ひつよう?
        return token(params);
    }
    
    /**
     * authからtokenまで全部込みにする予定.
     * @throws java.net.URISyntaxException
     * @throws java.io.IOException
     * @throws net.siisise.oauth.client.OAuthException
     * @deprecated まだ
     * @return 
     */
    public JSONObject token() throws URISyntaxException, IOException, OAuthException {
        JSONObject params = new JSONObject();
        if ( access == null ) { // 初期化がひつようなのでリダイレクト発動
            callbackLocalServer(new URI(redirect), this::authCb);
//            URI rd = createSecureAuth("code", scope);
            throw new OAuthException();
        } else if ( access.refreshToken == null ) {
            
        } else {
            params.put("grant_type", "refresh_token");
            params.put("refresh_toekn", access.refreshToken);
        }
        params.put("redirect_uri", redirect);
        throw new UnsupportedOperationException();
    }
    
    public JSONObject token(JSONObject params) throws IOException, RestException, URISyntaxException {
        setBasicAuthorization(info.clientId(), info.secret());
        JSONObject res = (JSONObject) post(info.tokenUri(), params);
        if ( access == null ) {
            access = new AccessInfo(info);
        }
        access.accessToken = (String)res.get("access_token");
        access.refreshToken = (String)res.get("reflesh_token");
        access.tokenType = (String)res.get("token_type");
        access.expiresIn = ((Number)res.get("expires_in")).intValue();
        setAccessToken(access.accessToken);
        return res;
    }
    
    /**
     * mastodon
     * @throws net.siisise.rest.RestException
     * @throws java.io.IOException
     * @throws java.net.URISyntaxException
     */
    public void revokeToken() throws RestException, IOException, URISyntaxException {
        JSONObject res = (JSONObject) post("revoke",
                "client_id", info.clientId(),
                "client_secret", info.secret(),
                "token", access.accessToken);
    }

}
