/*
 * Copyright 2023 okome.
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
package net.siisise.net;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.siisise.json.JSONObject;
import net.siisise.rest.RestClient;
import net.siisise.rest.RestException;

/**
 * HTTPS のみ
 */
public class WebFinger {
    
    
    /**
     * RFC 7033 WebFinger.
     * subject
     * aliases (Mastodon)
     * links
     * がある想定.
     * 
     * @param account ドメイン含まず
     * @param server
     * @return JSON Resource Descpritor (JRD)
     * @throws IOException
     * @throws RestException
     */
    public static JSONObject acct(String account, String server) throws IOException, RestException {
        
        RestClient rc = new RestClient("https://" + server, null);
        Map<String,String> param = new HashMap<>();
        param.put("resource", "acct:" + account + '@' + server);
        rc.addHeader("Accept", "application/jrd+json,application/json,*/*;q=0.8");
        return rc.get("/.well-known/webfinger", param);
    }

    /**
     * 
     * @param resource
     * @param rel
     * @return JRD
     * @throws java.io.IOException
     * @throws net.siisise.rest.RestException
     */
    public static JSONObject webFinger(URI resource, String... rel) throws IOException, RestException {
        String host;
        if ( resource.isOpaque() ) { // 不透明
            String sp = resource.getSchemeSpecificPart();
            String[] split = sp.split("@");
            host = split[split.length - 1];
        } else {
            host = resource.getHost();
        }
        
        RestClient rc = new RestClient("https://" + host, null);
        List<String> param = new ArrayList<>();
        param.add("resource");
        param.add( resource.toASCIIString());
        for ( String r : rel ) {
            param.add("rel");
            param.add(r);
        }
        rc.addHeader("Accept", "application/jrd+json,application/json,*/*;q=0.8");
        return rc.get("/.well-known/webfinger", param.toArray(new String[0]));
    }
}
