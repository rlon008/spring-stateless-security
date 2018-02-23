package nz.co.katatech.springboot.security.stateless.csrf;

import nz.co.katatech.springboot.security.stateless.HttpServletBinder;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.logging.Logger;

/**
 * An implementation that protect agains Cross Site Request Forgery by checking Origin & Referer header, see:
 * https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
 */

public class OriginAndRefererCsrfPreventionHttpServletBinder extends AbstractXSRFPreventionHttpServletBinder {
    private static final String REFERER_HEADER_KEY = "Referer";
    private static final String ORIGIN_HEADER_KEY = "Origin";
    private Logger logger = Logger.getLogger( OriginAndRefererCsrfPreventionHttpServletBinder.class.getName() );

    private final List<String> validDomains;

    public OriginAndRefererCsrfPreventionHttpServletBinder( HttpServletBinder<Authentication> delegate, List<String> validDomains ) {
        super( delegate );
        this.validDomains = validDomains;
    }

    protected boolean isValidRequest( HttpServletRequest request ) {
        if(validDomains.isEmpty()) {
            logger.warning( "No valid domain configured. CSRF prevention through Origin & Referrer " +
                    "header checks will be disabled. You can configure valid domains via property spring.security." +
                    "stateless.csrf.validDomains=domain1,domain2,domain3"
            );
            return true;
        }

        String source = getSource( request );
        if ( StringUtils.isEmpty( source ) ) {
            return false;
        }

        for ( String validDomain : validDomains ) {
            String prefix = validDomain.endsWith( "/" ) ? validDomain : validDomain + "/";
            if ( source.equals( validDomain ) || source.startsWith( prefix ) ) {
                return true;
            }
        }
        return false;
    }

    private String getSource( HttpServletRequest request ) {
        String origin = request.getHeader( ORIGIN_HEADER_KEY );
        if ( !StringUtils.isEmpty( origin ) ) {
            return origin.endsWith( "/" ) ? origin : (origin + "/");
        }

        return request.getHeader( REFERER_HEADER_KEY );
    }

}
