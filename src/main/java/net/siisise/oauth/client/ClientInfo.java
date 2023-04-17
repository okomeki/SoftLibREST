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
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import net.siisise.abnf.rfc.URI3986;
import net.siisise.io.FileIO;
import net.siisise.json.JSON;
import net.siisise.json.JSONArray;
import net.siisise.json.JSONObject;
import net.siisise.json.JSONValue;

/**
 * サービス情報.
 * accessToeknを取得するまでの基本情報的なもの
 * APIから得られる情報は含まない.
 */
public class ClientInfo {
    
    // 識別名
//    String name;

    // client id
    public final String id;
    // client secret
    public final String secret;
    // アクセス権 (メモ?)

    // https://accounts.google.com/.well-known/openid-configuration
    // https://auth.login.yahoo.co.jp/yconnect/v2/.well-known/openid-configuration など
    public String configUri;
//    public String authorizeUri;
//    public String tokenUri;
    // String redirectUri;

    // OpenID Connect
    public String iss;
    public JSONObject config;
    public JSONArray jwks;

    /**
     * OpenID Connect well-known + RS256
     * @param issuer issuer uri
     * @param clientId client id
     * @param secret client secret
     * @throws java.net.URISyntaxException
     * @throws java.io.IOException
     */
    public ClientInfo(String issuer, String clientId, String secret) throws URISyntaxException, IOException {
        this.iss = issuer;
        id = clientId;
        this.secret = secret;
        configUri = this.iss + (issuer.endsWith("/") ? "": "/") + ".well-known/openid-configuration";
        loadConfig(new URL(configUri));
    }

    /**
     * OpenID Connect openid-configuration + RS256
     * @param configuration openid-configuration
     * @param clientId client id
     * @param secret client secret
     * @throws IOException jkws uri のエラー
     * @throws java.net.MalformedURLException
     * @throws java.net.URISyntaxException
     */
    public ClientInfo(JSONObject configuration, String clientId, String secret) throws IOException, MalformedURLException, URISyntaxException {
        id = clientId;
        this.secret = secret;
        loadConfig(configuration);
    }
    
    static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    static final String TOKEN_ENDPOINT = "token_endpoint";
    static final String JWKS_URI = "jwks_uri";

    /**
     * 文字列で
     *
     * @param authUri authorize URI
     * @param tokenUri token URI
     * @param clientId クライアントID
     * @param secret クライアントシークレット
     * @throws java.net.URISyntaxException authorize URI, token URI が間違っている
     */
    public ClientInfo(String authUri, String tokenUri, String clientId, String secret) throws URISyntaxException {
        JSONObject conf = new JSONObject();
        conf.put(AUTHORIZATION_ENDPOINT, authUri);
        conf.put(TOKEN_ENDPOINT, tokenUri);
        try {
            loadConfig(conf);
        } catch (IOException ex) {
            // jwks読みない
        }
        id = clientId;
        this.secret = secret;
    }
    
    static JSONValue readJSON(URL url) throws IOException {
        byte[] bin = FileIO.binRead(url);
        return JSON.parseWrap(bin);
    }
    
    final void loadConfig(URL url) throws IOException, URISyntaxException {
        loadConfig((JSONObject)readJSON(url));
    }

    final void loadConfig(JSONObject configuration) throws IOException, URISyntaxException {
        String uri = (String)configuration.get(AUTHORIZATION_ENDPOINT);
        if ( !URI3986.URIreference.is(uri)) {
            throw new java.net.URISyntaxException(uri, "authorize URI");
        }
        uri = (String)configuration.get(TOKEN_ENDPOINT);
        if ( !URI3986.URIreference.is(uri)) {
            throw new java.net.URISyntaxException(uri, "token URI");
        }
        config = configuration;
    }

    public String authuri() {
        return (String)config.get(AUTHORIZATION_ENDPOINT);
    }

    public String tokenUri() {
        return (String)config.get(TOKEN_ENDPOINT);
    }

    public String clientId() {
        return id;
    }

    public String secret() {
        return secret;
    }

    /**
     * OpenID Connect scope
     * @return supported scopes list
     */
    public List<String> scopesSupported() {
        return (JSONArray)config.getJSON("scopes_supported");
    }
    
    public JSONArray idTokenSigningAlgValuesSupported() {
        return (JSONArray)config.getJSON("id_token_signing_alg_values_supported");
    }
    
    /**
     * RFC 7517 JWKっぽい?
     * @return
     * @throws MalformedURLException
     * @throws IOException 
     */
    public JSONArray keys() throws MalformedURLException, IOException {
        if ( jwks == null ) {
            String jwksUri = (String)config.get(JWKS_URI);
            if ( jwksUri != null ) {
                JSONValue  jkws = readJSON(new URL(jwksUri));
                jwks = (JSONArray)((JSONObject)jkws).getJSON("keys");
            }
        }
        return jwks;
    }
    
    public JSONObject alg(String alg, String kid) throws IOException {
        if ( jwks == null ) {
            keys();
        }
        for ( Object k : jwks ) {
            JSONObject key = (JSONObject)k;
            if ( alg.equals(key.get("alg")) && kid.equals(key.get("kid"))) {
                return key;
            }
        }
        throw new SecurityException();
    }

    public JSONArray codeChallengeMethodsSupported() {
        return (JSONArray)config.get("code_challenge_methods_supported");
    }
}
