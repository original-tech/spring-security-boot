package com.original.frame.core;

import java.util.Map;

public interface Message<T> {
    String getLocationUri();

    void setLocationUri(String uri);

    T getBody();

    void setBody(T body);

    String getHeader(String name);

    void addHeader(String name, String header);

    Map<String, String> getHeaders();

    void setHeaders(Map<String, String> headers);
}
