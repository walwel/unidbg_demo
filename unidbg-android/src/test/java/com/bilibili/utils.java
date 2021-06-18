package com.bilibili;

import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

public class utils {
    private static final char[] f2001c = "0123456789ABCDEF".toCharArray();
    public static final String FIELD_DELIMITER = "&";
    public static final String KEY_VALUE_DELIMITER = "=";


    private static boolean a(char c2, String str) {
        return (c2 >= 'A' && c2 <= 'Z') || (c2 >= 'a' && c2 <= 'z') || !((c2 < '0' || c2 > '9') && "-_.~".indexOf(c2) == -1 && (str == null || str.indexOf(c2) == -1));
    }

    static String b(String str) {
        return c(str, (String) null);
    }

    static String c(String str, String str2) {
        StringBuilder sb = null;
        if (str == null) {
            return null;
        }
        int length = str.length();
        int i2 = 0;
        while (i2 < length) {
            int i3 = i2;
            while (i3 < length && a(str.charAt(i3), str2)) {
                i3++;
            }
            if (i3 != length) {
                if (sb == null) {
                    sb = new StringBuilder();
                }
                if (i3 > i2) {
                    sb.append(str, i2, i3);
                }
                i2 = i3 + 1;
                while (i2 < length && !a(str.charAt(i2), str2)) {
                    i2++;
                }
                try {
                    byte[] bytes = str.substring(i3, i2).getBytes("UTF-8");
                    int length2 = bytes.length;
                    for (int i4 = 0; i4 < length2; i4++) {
                        sb.append('%');
                        sb.append(f2001c[(bytes[i4] & 240) >> 4]);
                        sb.append(f2001c[bytes[i4] & 15]);
                    }
                } catch (UnsupportedEncodingException e) {
                    throw new AssertionError(e);
                }
            } else if (i2 == 0) {
                return str;
            } else {
                sb.append(str, i2, length);
                return sb.toString();
            }
        }
        return sb == null ? str : sb.toString();
    }

    static String r(Map<String, String> map) {
        String str;
        if (!(map instanceof SortedMap)) {
            map = new TreeMap<>(map);
        }
        StringBuilder sb = new StringBuilder(256);
        for (Map.Entry next : map.entrySet()) {
            String str2 = (String) next.getKey();
            if (!str2.isEmpty()) {
                sb.append(b(str2));
                sb.append(KEY_VALUE_DELIMITER);
                String str3 = (String) next.getValue();
                if (str3 == null) {
                    str = "";
                } else {
                    str = b(str3);
                }
                sb.append(str);
                sb.append(FIELD_DELIMITER);
            }
        }
        int length = sb.length();
        if (length > 0) {
            sb.deleteCharAt(length - 1);
        }
        if (length == 0) {
            return null;
        }
        return sb.toString();
    }

}
