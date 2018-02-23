package nz.co.katatech.springboot.security.stateless;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StatelessSecurityContextRepository implements SecurityContextRepository {
    private final HttpServletBinder<Authentication> servletBinder;

    public StatelessSecurityContextRepository( HttpServletBinder<Authentication> servletBinder ) {
        this.servletBinder = servletBinder;
    }

    @Override
    public SecurityContext loadContext( HttpRequestResponseHolder requestResponseHolder ) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        Authentication authentication = servletBinder.retrieve( requestResponseHolder.getRequest() );
        if ( authentication != null ) {
            securityContext.setAuthentication( authentication );
        }
        return securityContext;
    }

    @Override
    public void saveContext( SecurityContext context, HttpServletRequest request, HttpServletResponse response ) {
        //do nothing
    }

    @Override
    public boolean containsContext( HttpServletRequest request ) {
        return false;
    }

}
