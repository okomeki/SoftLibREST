package net.siisise.net;

import java.net.URI;
import net.siisise.json.JSON;
import net.siisise.json.JSONArray;
import net.siisise.json.JSONObject;

/**
 * XRD の JSON版
 */
public class JRD implements RD<String> {
    JSONObject jrd;
    
    public JRD() {
        jrd = new JSONObject();
    }
    
    @Override
    public void subject(URI uri) {
        jrd.put("subject", uri.toString()); // 仮
    }
    
    /**
     * 有効期限
     * @param date YYYY-MM-DDThh:mm:ssZ っぽい整形済みだとする
     */
    @Override
    public void expires(String date) {
        jrd.put("expires", date);
    }

    @Override
    public void alias(URI alias) {
        JSONArray aliases = (JSONArray) jrd.get("aliases");
        if ( aliases == null ) {
            aliases = new JSONArray();
            jrd.put("aliases", aliases);
        }
        aliases.add(alias.toString());
    }

    @Override
    public void property(URI typeUri, String text) {
        
//        jrd.get("properties");
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void link(String rel, String type, URI href, String template) {
        
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void linkHref(String rel, URI href, String type) {
        link(rel, type, href, null);
    }
    
    @Override
    public void linkTemplate(String rel, String template, String type) {
        link(rel, type, null, template);
    }
    
    @Override
    public String get() {
        return (String) jrd.rebind(JSON.NOBR);
    }
}
