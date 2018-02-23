package nz.co.katatech.springboot.security.stateless;


import org.springframework.security.core.Authentication;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
        final String cookieToken = findToken( request );

        if ( cookieToken != null ) {
            try {
                String token = tokenParser.parse( cookieToken );
                return authenticationConverter.convert( token );
            } catch ( Exception ignored ) {
            }
        }

        return null;
    }

    public XAuthTokenHttpServletBinder withCookiePath( String path ) {
        this.path = path;
        return this;
    }

    private String findToken( HttpServletRequest request ) {
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
