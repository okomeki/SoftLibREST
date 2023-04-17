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
import java.net.Socket;

/**
 * WebSocket っぽいなにか Client篇.
 * 主? RFC 6455, 8307
 * RFC 8615
 */
public class WebSocket {
    Socket soc;
    private InputStream in;
    private final OutputStream out;

    public WebSocket(Socket soc) throws IOException {
        this.soc = soc;
        in = soc.getInputStream();
        out = soc.getOutputStream();
    }
    
}
