package com.original.frame.core;

import com.alibaba.fastjson.JSON;

import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class Response<T> implements Message<T> {

    protected int code;
    protected String uri = "";
    protected String msg = "";
    protected T body;
    protected final long timestamp = System.currentTimeMillis();
    protected Map<String, String> headers = new HashMap<>();

    public static <U> ResponseBuilder<U> withBuilder(int code, U body) {
        return new ResponseBuilder<>(code, body);
    }

    public static <U> ResponseBuilder<U> withBuilder(int code) {
        return new ResponseBuilder<>(code);
    }

    public static <U> ResponseBuilder<U> successBuilder(U body) {
        return new ResponseBuilder<>(HttpServletResponse.SC_OK, body);
    }

    public static <U> ResponseBuilder<U> errorBuilder(U body) {
        return new ResponseBuilder<>(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, body);
    }

    public static <U> ResponseBuilder<U> errorBuilder() {
        return new ResponseBuilder<>(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, null);
    }

    @Override
    public String getLocationUri() {
        return uri;
    }

    @Override
    public void setLocationUri(String uri) {
        this.uri = uri;
    }

    @Override
    public T getBody() {
        return body;
    }

    @Override
    public void setBody(T body) {
        this.body = body;
    }

    @Override
    public String getHeader(String name) {
        return headers.get(name);
    }

    @Override
    public void addHeader(String name, String header) {
        headers.put(name, header);
    }

    @Override
    public Map<String, String> getHeaders() {
        return headers;
    }

    @Override
    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public long getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return JSON.toJSONString(this);
    }

    public static class ResponseBuilder<T> {
        private final Response<T> response;

        public ResponseBuilder() {
            this.response = new Response<>();
        }

        public ResponseBuilder(int code) {
            this.response = new Response<>();
            this.response.setCode(code);
        }

        public ResponseBuilder(int code, T body) {
            this.response = new Response<>();
            this.response.setCode(code);
            this.response.setBody(body);
        }

        public ResponseBuilder<T> location(String location) {
            response.setLocationUri(location);
            return this;
        }

        public ResponseBuilder<T> body(T body) {
            response.setBody(body);
            return this;
        }

        public ResponseBuilder<T> msg(String msg) {
            response.setMsg(msg);
            return this;
        }

        public ResponseBuilder<T> addHeader(String name, String header) {
            response.addHeader(name, header);
            return this;
        }

        public ResponseBuilder<T> setHeaders(Map<String, String> headers) {
            response.setHeaders(headers);
            return this;
        }

        public Response<T> build() {
            return response;
        }
    }
}
