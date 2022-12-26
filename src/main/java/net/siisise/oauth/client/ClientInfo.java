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

import java.net.URISyntaxException;
import net.siisise.abnf.rfc.URI3986;

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

    //
    public final String authorizeUri;
    public final String tokenUri;
    // String redirectUri;
    
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
        if ( !URI3986.URIreference.is(authUri)) {
            throw new java.net.URISyntaxException(authUri, "authorize URI");
        }
        if ( !URI3986.URIreference.is(tokenUri)) {
            throw new java.net.URISyntaxException(authUri, "token URI");
        }
        this.authorizeUri = authUri;
        this.tokenUri = tokenUri;
        id = clientId;
        this.secret = secret;
    }

    public String authuri() {
        return authorizeUri;
    }

    public String tokenUri() {
        return tokenUri;
    }

    public String clientId() {
        return id;
    }

    public String secret() {
        return secret;
    }

}
