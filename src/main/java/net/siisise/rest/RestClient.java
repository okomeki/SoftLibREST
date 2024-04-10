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
package net.siisise.rest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.siisise.bind.Rebind;
import net.siisise.io.FileIO;
import net.siisise.net.http.HttpClient;
import net.siisise.json.JSON;
import net.siisise.json.JSONValue;

/**
 * JSONを使うのでSoftLibに置けない仮置き場
 * 
 * post www-
 * post blob
 * post JSON
 * 3つくらいに対応する.
 */
public class RestClient extends HttpClient {

    /**
     * 
     * Nature Remo っぽい
     * @param baseURI
     * @param accessToken 
     */
    public RestClient(String baseURI, String accessToken) {
/*
        URL uri;
        try {
            uri = new URL(baseURI);
            headers.put("Host", uri.getHost());
        } catch (MalformedURLException ex) {
            Logger.getLogger(RestClient.class.getName()).log(Level.SEVERE, null, ex);
        }
*/        
        headers.put("Accept", "application/json,*/*;q=0.8");
        baseuri = baseURI;
        setAccessToken(accessToken);
    }
    
    /**
     * RFC 6750 OAuth 2.0 Bearer
     * @param accessToken 
     */
    public final void setAccessToken(String accessToken) {
        if (accessToken != null) {
            headers.put("Authorization", "Bearer " + accessToken);
        } else {
            headers.remove("Authorization");
        }
    }

    /**
     * パラメータを適度に追加する.
     * @param uri
     * @param nv
     * @return
     */
    public static URI param(String uri, String... nv) {
        StringBuilder u = new StringBuilder(uri);
        char ar = '?';
        for (int i = 0; i < nv.length; i += 2) {
            u.append(ar);
            u.append(formPercentEncode(nv[i]));
            u.append("=");
            u.append(formPercentEncode(nv[i + 1]));
            ar = '&';
        }
        return URI.create(u.toString());
    }

    /**
     * 
     * @param uri
     * @param params
     * @return 
     */
    public static URI param(String uri, Map<String,String> params) {
        StringBuilder u = new StringBuilder(uri);
        char ap = '?';
        for ( String key : params.keySet() ) {
            u.append(ap);
            u.append(formPercentEncode(key));
            u.append("=");
            u.append(formPercentEncode(params.get(key)));
            ap ='&';
        }
        return URI.create(u.toString());
    }

    /**
     * 
     * @param url
     * @param name
     * @param nv
     * @return 
     */
    public static String html(String url, String name, String... nv) {
        StringBuilder html = new StringBuilder();
        html.append("<form action=\"");
        html.append(url);
        html.append("\">");
        for (int i = 0; i < nv.length; i += 2) {
            html.append("<input type=\"hidden\" name=\"");
            html.append(formPercentEncode(nv[i]));
            html.append("\" value=\"");
            html.append(formPercentEncode(nv[i + 1]));
            html.append("\">");
        }
        html.append("<input type=\"submit\">");
        html.append("</form>");
        return html.toString();
    }

    /**
     * 
     * @param <T>
     * @param uri 相対URL
     * @param params
     * @return
     * @throws RestException
     * @throws IOException
     */
    public <T> T get(String uri, String... params) throws RestException, IOException {
        if (params.length >= 2) {
            return get(param(baseuri + uri,params), JSONValue.class);
        }
        return get(URI.create(baseuri + uri), JSONValue.class);
    }

    /**
     * GET
     * @param uri
     * @param accept content-type
     * @param params
     * @return bin
     * @throws IOException 
     */
    public byte[] getBlob(String uri, String accept, String... params) throws IOException {
        URI u = param(baseuri + uri, params);
        return getBlob(u, accept);
    }

    /**
     * GET
     * @param <T>
     * @param uri
     * @param paramMap
     * @return
     * @throws RestException
     * @throws IOException 
     */
    public <T> T get(String uri, Map<String, String> paramMap) throws RestException, IOException {
        return get(param(baseuri + uri, paramMap));
    }

    /**
     * GET JSON
     * @param <T> たぶんJSON
     * @param uri 完全URL
     * @return JSONな戻りを期待
     * @throws RestException
     * @throws IOException 
     */
    public <T> T get(URI uri) throws RestException, IOException {
        return get(uri, JSONValue.class);
    }

    /**
     * fieldから型情報を取得してその形で戻り値を返す
     *
     * @param <T>
     * @param url 相対URL
     * @param field 代入するフィールド ここから型情報を取得する
     * @return
     * @throws net.siisise.rest.RestException
     * @throws IOException
     * @throws URISyntaxException
     */
    public <T> T get(String url, Field field) throws RestException, IOException, URISyntaxException {
        return get(url, field.getGenericType());
    }

    /**
     * 特定の戻り型でGET 
     * @param <T>
     * @param url 相対URL
     * @param genType 期待する戻り型
     * @return
     * @throws net.siisise.rest.RestException
     * @throws IOException
     */
    public <T> T get(String url, Type genType) throws RestException, IOException {
        return get(URI.create(baseuri + url), genType);
    }

    /**
     * HTTP GET パラメータ未対応
     *
     * @param <T>
     * @param uri 完全URL
     * @param type 期待する戻り型
     * @return JSON固定 bindとかしない
     * @throws net.siisise.rest.RestException
     * @throws IOException
     */
    public <T> T get(URI uri, Type type) throws RestException, IOException {
        HttpURLConnection conn = getConnect(uri);
        return result(conn, type);
    }

    /**
     * GET でバイト列として取得.
     * @param uri
     * @param accept content-type
     * @return result bin
     * @throws IOException 
     */
    public byte[] getBlob(URI uri, String accept) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        conn.setRequestMethod("GET");

        Map<String,String> hds = new LinkedHashMap<>(headers);
        hds.put("accept", accept);

        hds.forEach((key, val) -> conn.setRequestProperty(key, val));
        return FileIO.binRead(conn.getInputStream());
    }

    /**
     * body にパラメータ入れる
     * @param uri
     * @param paramMap
     * @return
     * @throws RestException
     * @throws IOException 
     */
    public JSONValue post(String uri, Map<String, String> paramMap) throws RestException, IOException {
        return post(URI.create(baseuri + uri), paramMap);
    }
    
    /**
     * パラメータをJSONにまとめて送信.
     * @param <T>
     * @param uri
     * @param json
     * @return
     * @throws IOException
     * @throws RestException 
     */
    public <T extends JSONValue> T postJSON(String uri, JSONValue json) throws IOException, RestException {
        return post(URI.create(baseuri + uri), "application/json", 
                json.rebind(JSONValue.NOBR_MINESC).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * JSON なし
     * @param <T>
     * @param uri
     * @return
     * @throws IOException
     * @throws RestException 
     */
    public <T extends JSONValue> T post(String uri) throws IOException, RestException {
        return post(URI.create(baseuri + uri), null, null);
    }

    public <T extends JSONValue> T post(String uri, String mime, byte[] body) throws IOException, RestException {
        return post(URI.create(baseuri + uri), mime, body);
    }

    /**
     * POST 一般的な
     * @param uri
     * @param parameters 名と値のペア
     * @return
     * @throws RestException
     * @throws IOException
     */
    public JSONValue post(String uri, String... parameters) throws RestException, IOException {
        return post(URI.create(baseuri + uri), parameters);
    }

    /**
     * POST body にパラメータを入れる
     * @param uri
     * @param paramMap
     * @return
     * @throws RestException
     * @throws IOException 
     */
    public JSONValue post(URI uri, Map<String, String> paramMap) throws RestException, IOException {
        return post(uri, paramToArray(paramMap));
    }
    
    String[] paramToArray(Map<String, String> paramMap) {
        List<String> params = new ArrayList<>();
        paramMap.forEach((key, val) -> {
            params.add(key);
            params.add(val);
        });
        return params.toArray(new String[0]);
    }

    /**
     * POST.application/x-www-form-urlencoded
     * エラーは Exception で
     * @param uri
     * @param parameters エンコードしてない
     * @return JSON
     * @throws net.siisise.rest.RestException
     * @throws IOException
     */
    public JSONValue post(URI uri, String... parameters) throws RestException, IOException {
        HttpURLConnection conn = postRequest(uri, parameters);
        return result(conn, JSONValue.class);
    }

    /**
     * POST application/json
     * @param <T>
     * @param uri
     * @param json
     * @return
     * @throws IOException
     * @throws RestException 
     */
    public <T extends JSONValue> T postJSON(URI uri, JSONValue json) throws IOException, RestException {
        return post(uri, "application/json", json.toJSON().getBytes(StandardCharsets.UTF_8));
    }
    
    /**
     * BODY送信
     * @param <T>
     * @param uri
     * @param mime
     * @param body
     * @return
     * @throws IOException
     * @throws RestException 
     */
    public <T extends JSONValue> T post(URI uri, String mime, byte[] body) throws IOException, RestException {
        HttpURLConnection conn = postConnect(uri);
        
        System.out.println(new String(body, StandardCharsets.UTF_8));

        if (body != null) {
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", mime);
            conn.setRequestProperty("Content-Length", "" + body.length);
            OutputStream out = conn.getOutputStream();
            out.write(body);
            out.flush();
        }
        return result(conn, JSONValue.class);
    }

    /**
     * 
     * @param uri
     * @return
     * @throws MalformedURLException
     * @throws ProtocolException
     * @throws IOException 
     */
    HttpURLConnection getConnect(URI uri) throws MalformedURLException, ProtocolException, IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        // https限定
        conn.setRequestMethod("GET");
        headers.forEach((key, val) -> conn.setRequestProperty(key, val));
/*
        System.out.println("S: GET " + uri.toString());
        Map<String, List<String>> rp = conn.getRequestProperties();
        System.out.println();
        System.out.println("GET " + uri.toString());
        for ( String key : rp.keySet() ) {
            for ( String v : rp.get(key)) {
                System.out.println("S: " + key + ": " + v);
            }
        }
        System.out.println();
*/
        return conn;
    }

    /**
     * 
     * @param uri
     * @return
     * @throws MalformedURLException
     * @throws ProtocolException
     * @throws IOException 
     */
    HttpURLConnection postConnect(URI uri) throws MalformedURLException, ProtocolException, IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        // https限定
        conn.setRequestMethod("POST");
        headers.forEach((key, val) -> conn.setRequestProperty(key, val));
/*
        System.out.println("S: POST " + uri.toString());
        Map<String, List<String>> rp = conn.getRequestProperties();
        System.out.println();
        System.out.println("POST " + uri.toString());
        for ( String key : rp.keySet() ) {
            for ( String v : rp.get(key)) {
                System.out.println("S: " + key + ": " + v);
            }
        }
        System.out.println();
*/
        return conn;
    }

    /**
     * 
     * @param uri
     * @param parameters body encode parameter
     * @return
     * @throws IOException 
     */
    HttpURLConnection postRequest(URI uri, String... parameters) throws IOException {
        HttpURLConnection conn = postConnect(uri);
        
        if (parameters.length > 0) {
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parameters.length; i += 2) {
                if (sb.length() > 0) {
                    sb.append('&');
                }
                sb.append(formPercentEncode(parameters[i]));
                sb.append('=');
                sb.append(formPercentEncode(parameters[i + 1]));
            }
            byte[] utf = sb.toString().getBytes(StandardCharsets.UTF_8);
            conn.setRequestProperty("Content-Length", "" + utf.length);
            OutputStream out = conn.getOutputStream();
            out.write(utf);
            out.flush();
        }
        return conn;
    }

    /**
     *
     * @param conn
     * @param type 期待する戻り型
     * @return JSON
     * @throws IOException
     */
    private <T> T result(HttpURLConnection conn, Type type) throws IOException, RestException {
        conn.connect();
        int code = conn.getResponseCode();
        System.out.print(code + " ");
        System.out.println(conn.getResponseMessage());
        // conn.getResponseCode();
        //conn.getHeaderFields();
        Map<String, List<String>> hfs = conn.getHeaderFields();
        for ( String key : hfs.keySet() ) {
            List<String> vs = hfs.get(key);
            for ( String v : vs ) {
                System.out.println("R: " + key + ": " + v);
            }
        }
        
        String contentType = conn.getContentType();
        System.out.println("content-type: " + contentType);

        InputStream in;
        if ( code >= 400 ) {
            in = conn.getErrorStream();
        } else {
            in = conn.getInputStream();
        }

        byte[] result = FileIO.binRead(in);
        System.out.println(new String(result, StandardCharsets.UTF_8));
        conn.disconnect();
        if ( code >= 400 ) {
            throw new RestException(code, conn.getResponseMessage(), conn.getContentType(), result);
        }
        return Rebind.valueOf(JSON.parse(result), type);
//                JSON.parseWrap(result);
    }
}
