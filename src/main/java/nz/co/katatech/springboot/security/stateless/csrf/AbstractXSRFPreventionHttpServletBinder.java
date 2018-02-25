package nz.co.katatech.springboot.security.stateless.csrf;

import nz.co.katatech.springboot.security.stateless.HttpServletBinder;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;


public abstract class  AbstractXSRFPreventionHttpServletBinder implements HttpServletBinder<Authentication> {

    private final List<String> protectedMethods;
    private final HttpServletBinder<Authentication> delegate;

    public AbstractXSRFPreventionHttpServletBinder( List<String> protectedMethods, HttpServletBinder<Authentication> delegate ) {
        this.protectedMethods = protectedMethods;
        this.delegate = delegate;
    }

    public AbstractXSRFPreventionHttpServletBinder( HttpServletBinder<Authentication> delegate ) {
        this( Arrays.asList( "POST", "PATCH", "PUT", "DELETE" ), delegate );
    }

    @Override
    public Authentication retrieve( HttpServletRequest request ) {
        if ( requirePrevention( request.getMethod() ) && !isValidRequest( request ) ) {
            return null;
        }

        return delegate.retrieve( request );
    }

    private boolean requirePrevention( String method ) {
        return protectedMethods.contains( method );
    }

    @Override
    public void bind( HttpServletResponse response, Authentication authentication ) {
        delegate.bind( response, authentication );
    }

    protected abstract boolean isValidRequest( HttpServletRequest request );
}
