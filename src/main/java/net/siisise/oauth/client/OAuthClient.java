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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.siisise.json.JSONObject;
import net.siisise.net.HttpClient;
import net.siisise.net.HttpServer;
import net.siisise.rest.RestClient;
import net.siisise.rest.RestException;

/**
 * OAuthのClient としていろいろ使える準備.
 */
public class OAuthClient extends RestClient {

    public static final String OOB = "urn:ietf:wg:oauth:2.0:oob";

    private AccessInfo access;
    private final ClientInfo info;

    private String redirect;
    private String state;
    private HttpServer httpd;

    /**
     * サーバに登録されたClient ID, Client Secret を知っている状態からスタート.
     * @param info client 情報
     */
    public OAuthClient(ClientInfo info) {
        super("", null);
        this.info = info;
    }

    public ClientInfo info() {
        return info;
    }

    /**
     * callback から token 取得まで行う.
     * @param cb
     * @return 
     */
    public JSONObject callback(JSONObject cb) {
        System.out.println("callback");
        String method = (String)cb.get("method");
        // ? から # までのあいだ
        String queryLine = (String)cb.get("query");
        Map<String,String> query = null;
        if ( queryLine != null ) {
            query = HttpClient.decodeQuery(queryLine);
        }
//        URI3986.REG.find(rt, "", subrulenames); // 次 URI6874
        String code = query.get("code");
        JSONObject exr = new JSONObject();
        exr.put("all", cb);
        exr.put("method", method);

        exr.put("query",query);

        if ( code == null || !state.equals(query.get("state")) ) {
            return new JSONObject();
        }
        try {
            exr.putJSON("ac",authcode(code));
            return exr;
        } catch (IOException ex) {
            Logger.getLogger(OAuthClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (URISyntaxException ex) {
            Logger.getLogger(OAuthClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (RestException ex) {
            Logger.getLogger(OAuthClient.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return exr; //authcode(code);
       // return new JSONObject();
    }

    /**
     * リダイレクト先がある場合は指定したり
     * @param redirect
     * @param scope
     * @return 
     * @throws java.io.IOException callbackサーバ作れなかった
     * @throws java.security.NoSuchAlgorithmException
     */
    public URI authLink(String redirect, String scope) throws IOException, NoSuchAlgorithmException {
        long rnd = java.security.SecureRandom.getInstanceStrong().nextLong();
        state = Long.toHexString(rnd); // 仮
        if (redirect == null || redirect.isEmpty()) {
            this.redirect = callbackLocalServer(9099, "/oauth-web-client/authd", this::callback);
        } else {
            this.redirect = redirect;
        }
        JSONObject params = new JSONObject();
        params.put("response_type", "code");
        params.put("client_id", info.clientId());
        params.put("redirect_uri", this.redirect);
        if ( scope != null ) {
            params.put("scope", scope);
        }
        params.put("state", state);
        URI authp = param(info.authuri(), params);
        return authp;
    }

    /**
     * httpd 受け付け専用のhttpdを立ててみる無謀な計画.
     * @return url
     */
    String callbackLocalServer(int port, String path, Function<JSONObject,JSONObject> callback) throws IOException {
        httpd = new HttpServer();
        httpd.callback(callback);
        port = httpd.start(port);
        return "http://localhost:" + port + path;
    }
    
    public void close() throws IOException {
        if ( httpd != null ) {
            httpd.close();
            httpd = null;
        }
    }

    /**
     * token 1回目
     * access token を取得する.
     * @param code
     * @return
     * @throws java.io.IOException
     * @throws java.net.URISyntaxException
     * @throws net.siisise.rest.RestException 
     */
    public JSONObject authcode(String code) throws IOException, URISyntaxException, RestException {
        JSONObject res = (JSONObject) post(info.tokenUri(),
                "grant_type", "authorization_code",
                "code", code,
                "redirect_uri", this.redirect,
                "client_id", info.clientId(),
                "client_secret", info.secret());
        String at = (String) res.get("access_token");
        setAccessToken(at);
        return res;
    }

    /**
     * refresh token をつかう
     * @return 
     * @throws net.siisise.rest.RestException 
     * @throws java.io.IOException 
     * @throws java.net.URISyntaxException 
     */
    public JSONObject refresh() throws RestException, IOException, URISyntaxException {
        JSONObject res = (JSONObject) post(info.tokenUri(),
                "grant_type", "client_credentials",
                "client_id", info.clientId(),
                "client_secret", info.secret(),
                "redirect_uri", this.redirect);
        access.accessToken = (String)res.get("access_token");
        access.refreshToken = (String)res.get("reflesh_token");
        res.get("expire_in");
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
