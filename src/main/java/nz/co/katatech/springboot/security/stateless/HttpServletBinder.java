package nz.co.katatech.springboot.security.stateless;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface HttpServletBinder<T> {
    String X_AUTH_TOKEN = "X-AUTH-TOKEN";

    T retrieve( HttpServletRequest request );

    void bind( HttpServletResponse response, T value );
}