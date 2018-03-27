package nz.co.katatech.springboot.security.stateless;


import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.springframework.util.StringUtils.isEmpty;

public class XAuthTokenHttpServletBinder implements HttpServletBinder<Authentication> {
    private final TokenParser<String> tokenParser;
    private String path = "/";
    private AuthenticationConverter<String> authenticationConverter;

    public XAuthTokenHttpServletBinder( TokenParser<String> tokenParser, AuthenticationConverter<String> authenticationConverter ) {
        this.tokenParser = tokenParser;
        this.authenticationConverter = authenticationConverter;
    }

    @Override
    public void bind( HttpServletResponse response, Authentication authentication ) {
        String subject = authenticationConverter.convert( authentication );
        final String token = tokenParser.generate( subject );
        final Cookie cookie = new Cookie( X_AUTH_TOKEN, token );
        cookie.setPath( path );
        cookie.setHttpOnly( true );
        response.addCookie( cookie );
    }

    @Override
    public Authentication retrieve( HttpServletRequest request ) {
        final String token = getToken( request );
        if ( token != null ) {
            try {
                String parsedToken = tokenParser.parse( token );
                return authenticationConverter.convert( parsedToken );
            } catch ( Exception ignored ) {
            }
        }
        return null;
    }

    private String getToken( HttpServletRequest request ) {
        String headerToken = request.getHeader( X_AUTH_TOKEN );
        return !isEmpty( headerToken ) ? headerToken : findCookieToken( request );
    }

    public XAuthTokenHttpServletBinder withCookiePath( String path ) {
        this.path = path;
        return this;
    }

    private String findCookieToken( HttpServletRequest request ) {
        final Cookie[] cookies = request.getCookies();
        if ( cookies != null ) {
            for ( Cookie cookie : cookies ) {
                if ( X_AUTH_TOKEN.equals( cookie.getName() ) ) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
