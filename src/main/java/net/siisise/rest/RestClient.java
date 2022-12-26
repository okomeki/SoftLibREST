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
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.siisise.io.FileIO;
import net.siisise.net.HttpClient;
import net.siisise.json.bind.OMAP;
import net.siisise.json.JSON;
import net.siisise.json.JSONValue;

/**
 * JSONを使うのでSoftLibに置けない仮置き場
 */
public class RestClient extends HttpClient {
    
   
    // Nature Remo っぽい
    public RestClient(String baseURI, String accessToken) {
        headers.put("Accept", "application/json");
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
     *
     * @param uri
     * @param nv
     * @return
     */
    public static URI param(String uri, String... nv) {
        StringBuilder u = new StringBuilder(uri);
        for (int i = 0; i < nv.length; i += 2) {
            u.append(i == 0 ? "?" : "&");
            u.append(formPercentEncode(nv[i]));
            u.append("=");
            try {
                u.append(URLEncoder.encode(nv[i + 1], "utf-8"));
            } catch (UnsupportedEncodingException ex) {
                // ない
            }
        }
        return URI.create(u.toString());
    }

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

    public <T> T get(String uri) throws RestException, IOException, URISyntaxException {
        return get(uri, JSONValue.class);
    }

    public <T> T get(URI uri) throws RestException, IOException {
        return get(uri, JSONValue.class);
    }

    /**
     * fieldから型情報を取得してその形で戻り値を返す
     *
     * @param <T>
     * @param url
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
     *
     * @param <T>
     * @param url
     * @param genType 期待する戻り型
     * @return
     * @throws net.siisise.rest.RestException
     * @throws IOException
     * @throws URISyntaxException
     */
    public <T> T get(String url, Type genType) throws RestException, IOException, URISyntaxException {
        return get(new URI(baseuri + url), genType);
    }

    /**
     * HTTP GET パラメータ未対応
     *
     * @param <T>
     * @param uri
     * @param type 期待する戻り型
     * @return JSON固定 bindとかしない
     * @throws net.siisise.rest.RestException
     * @throws IOException
     */
    public <T> T get(URI uri, Type type) throws RestException, IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();

        headers.forEach((key, val) -> conn.setRequestProperty(key, val));

        return result(conn, type);
    }

    public JSONValue post(String uri, Map<String, String> paramMap) throws RestException, IOException, URISyntaxException {
        return post(new URI(baseuri + uri), paramMap);
    }

    public JSONValue post(String uri, String... parameters) throws RestException, IOException, URISyntaxException {
        return post(new URI(baseuri + uri), parameters);
    }

    public JSONValue post(URI uri, Map<String, String> paramMap) throws RestException, IOException {
        List<String> params = new ArrayList<>();
        paramMap.forEach((key, val) -> {
            params.add(key);
            params.add(val);
        });
        return post(uri, params.toArray(new String[0]));
    }

    /**
     * POST.application/x-www-form-urlencoded

 エラーは Exception で
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

    HttpURLConnection postRequest(URI uri, String... parameters) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        // https限定
        conn.setRequestMethod("POST");
        headers.forEach((key, val) -> conn.setRequestProperty(key, val));

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
        // conn.getResponseCode();
        //conn.getHeaderFields();
        String contentType = conn.getContentType();
        byte[] result = FileIO.binRead(conn.getInputStream());
        conn.disconnect();
        return OMAP.valueOf(JSON.parse(result), type);
//                JSON.parseWrap(result);
    }
}
