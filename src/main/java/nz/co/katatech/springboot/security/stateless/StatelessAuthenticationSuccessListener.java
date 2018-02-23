package nz.co.katatech.springboot.security.stateless;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;

public class StatelessAuthenticationSuccessListener implements ApplicationListener {

    private final HttpServletBinder<Authentication> servletBinder;

    @Resource
    private HttpServletResponse response;

    public StatelessAuthenticationSuccessListener( HttpServletBinder<Authentication> servletBinder ) {
        this.servletBinder = servletBinder;
    }

    @Override
    public void onApplicationEvent( ApplicationEvent event ) {
        if ( event instanceof AuthenticationSuccessEvent ) {
            Authentication authentication = ( (AuthenticationSuccessEvent) event ).getAuthentication();
            servletBinder.bind( response, authentication );
        }
    }
}
