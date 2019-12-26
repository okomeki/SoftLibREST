package net.siisise.net.rest;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import net.siisise.io.FileIO;
import net.siisise.json.JSON;
import net.siisise.json.JSONValue;

/**
 * JSONを使うのでSoftLibに置けない仮置き場
 */
public class RestClient {

    private final String accessToken;

    public RestClient(String accessToken) {
        this.accessToken = accessToken;
    }

    /**
     * HTTP GET パラメータ未対応
     *
     * @param uri
     * @return JSON固定 bindとかしない
     * @throws IOException
     */
    public JSONValue get(URI uri) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();

        conn.setRequestProperty("Accept", "application/json");
        if (accessToken != null) {
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        }
        conn.connect();

        return result(conn);
    }

    /**
     * POST. パラメータのエンコードしてない.
     *
     * @param uri
     * @param parameters エンコードしてない
     * @return
     * @throws IOException
     */
    public JSONValue post(URI uri, String... parameters) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
        // https限定
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Accept", "application/json");
        if (accessToken != null) {
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        }
        if (parameters.length > 0) {
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < parameters.length; i += 2) {
                if (sb.length() > 0) {
                    sb.append("&");
                }
                sb.append(parameters[i]);
                sb.append("=");
                sb.append(parameters[i + 1]);
            }
            byte[] utf = sb.toString().getBytes("utf-8");
            conn.setRequestProperty("Content-Length", "" + utf.length);
            OutputStream out = conn.getOutputStream();
            out.write(utf);
            out.flush();
        }

        conn.connect();

        return result(conn);
    }
    
    private JSONValue result(HttpURLConnection conn) throws IOException {
        byte[] result = FileIO.binRead(conn.getInputStream());
        conn.disconnect();
        return JSON.parse(result);
    }
}
