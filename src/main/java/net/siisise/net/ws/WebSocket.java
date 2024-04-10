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
package net.siisise.net.ws;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.net.Socket;
import java.net.URL;
import net.siisise.io.Input;

/**
 * WebSocket っぽいなにか Client篇.
 * 主? RFC 6455, 8307
 * RFC 8615
 */
public class WebSocket {

    Socket soc;
    private InputStream in;
    private final OutputStream out;
    private URL url;
    private final String protocol;
    
    public enum State {
        CONNECTING((short)0), // 0
        OPEN((short)1), // 1
        CLOSING((short)2), // 2
        CLOSED((short)3) // 3
        ;
        
        short n;
        
        State(short n) {
        this.n = n;
        }
        
        public short get() {
            return n;
        }
        
    }
    
    State state;
    
    /**
     * 
     * @param url 
     */
    public WebSocket(URL url) {
        this(url, null);
    }

    public WebSocket(URL url, String protocol) {
        this.protocol = protocol;
        this.url = url;
        in = null;
        out = null;
    }

    public WebSocket(Socket soc, String protocol) throws IOException {
        this.protocol = protocol;
        this.soc = soc;
        in = soc.getInputStream();
        out = soc.getOutputStream();
    }

    /**
     * 
     * @throws ProtocolException 
     */
    public void connect() throws ProtocolException {
        if ( state != null ) {
            throw new java.net.ProtocolException();
        }
        state = State.CONNECTING;
    }
    
    public String getProtocol() {
        return protocol;
    }

    public void close() throws IOException {
        soc.close();
    }

    public int available() throws IOException {
        return in.available();
    }

    public URL getURL() {
        return url;
    }

    public void send(String data) {

    }

    public void send(Input data) {

    }

    public void send(byte[] blob) {

    }

}
