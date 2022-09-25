package com.sample.ex;

import org.springframework.http.HttpStatus;

/**
 * 身份验证异常
 *
 * @author breeze
 * @date 2022-09-25
 */
public class AuthException extends RuntimeException {

    /**
     * 错误码
     */
    private Integer code;

    /**
     * 错误提示
     */
    private String msg;

    public AuthException(String msg, HttpStatus httpStatus) {
        super(msg);
        this.code = httpStatus.value();
        this.msg = msg;
    }
}
