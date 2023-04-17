package net.siisise.html;

/**
 * HTMLのエスケープなど.
 * どこに置くかは未定.
 */
public class HTML {
    
    public static String encode(char ch) {
        switch(ch) {
            case '&':
                return "&amp;";
            case '<':
                return "&lt;";
            case '>':
                return "&gt;";
            case '"':
                return "&quot;";
            case '\'':
                return "&#39;";
            case ' ':
                return "&nbsp;";
            default:
                return String.valueOf(ch);
        }
    }
    
    public static String esc(String src) {
        StringBuilder sb = new StringBuilder();
        char[] chs = src.toCharArray();
        for ( char ch : chs ) {
            String dec = encode(ch);
            sb.append(dec);
        }
        return sb.toString();
    }
}
