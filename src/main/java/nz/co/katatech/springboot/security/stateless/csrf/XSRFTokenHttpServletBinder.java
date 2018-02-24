package nz.co.katatech.springboot.security.stateless.csrf;

import nz.co.katatech.springboot.security.stateless.HttpServletBinder;
import org.springframework.security.core.Authentication;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class XSRFTokenHttpServletBinder extends AbstractXSRFPreventionHttpServletBinder {

    public static final String XSRF_TOKEN_COOKIE_NAME = "XSRF-TOKEN";
    public static final String XSRF_TOKEN_HEADER_NAME = "X-XSRF-TOKEN";


    public XSRFTokenHttpServletBinder( HttpServletBinder<Authentication> delegate ) {
        super( delegate );
    }

    @Override
    protected boolean isValidRequest( HttpServletRequest request ) {
        final String csrfTokenValue = request.getHeader( XSRF_TOKEN_HEADER_NAME );
        final Cookie[] cookies = request.getCookies();

        String csrfCookieValue = null;
        if ( cookies != null ) {
            for ( Cookie cookie : cookies ) {
                if ( cookie.getName().equals( XSRF_TOKEN_COOKIE_NAME ) ) {
                    csrfCookieValue = cookie.getValue();
                }
            }
        }
        return csrfTokenValue != null && csrfTokenValue.equals( csrfCookieValue );
    }

}
