package com.liangdengyu.payment.PQC.Demos;
import java.util.HashMap;
import java.util.Map;

public class JsonObjectExample {
    private Map<String, String> data = new HashMap<>();

    public void put(String key, String value) {
        data.put(key, value);
    }

    public String get(String key) {
        return data.get(key);
    }
}
