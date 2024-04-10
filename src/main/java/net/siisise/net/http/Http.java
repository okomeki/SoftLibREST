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
package net.siisise.net.http;

import java.net.URL;
import net.siisise.abnf.rfc.URI6874;
import net.siisise.block.ReadableBlock;
import net.siisise.bnf.BNF;
import net.siisise.net.ws.WebSocket;

/**
 * HTTP/2とか3とか
 */
public class Http {
    
    /**
     * 
     * @param uri
     * @return 
     */
    public Http connect(String uri) {
        BNF.Match uriMatch = parseURI(uri);
        
        throw new java.lang.UnsupportedOperationException("まだない");
    }

    /**
     * URI から scheme
     * @param uri
     * @return 
     */
    BNF.Match parseURI(String uri) {
        ReadableBlock uriBlock = ReadableBlock.wrap(uri);
        return URI6874.REG.find(uriBlock, "URI", "scheme", "userinfo", "host","port", "path-abempty", "query", "fragment");
    }
    
    void nego() {
        
    }
    
    public WebSocket socket(URL url) {
        return new WebSocket(url);
    }
    
}
