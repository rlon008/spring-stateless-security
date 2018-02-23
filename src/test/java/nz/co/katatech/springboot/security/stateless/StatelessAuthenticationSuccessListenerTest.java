package nz.co.katatech.springboot.security.stateless;

import nz.co.testamation.testcommon.template.MockitoTestTemplate;
import org.junit.Test;
import org.springframework.context.ApplicationEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletResponse;

public class StatelessAuthenticationSuccessListenerTest {

    abstract class Template extends MockitoTestTemplate {
        HttpServletBinder<Authentication> servletBinder = mock( HttpServletBinder.class );
        StatelessAuthenticationSuccessListener listener = new StatelessAuthenticationSuccessListener( servletBinder );

    }

    @Test
    public void happyDay() throws Exception {
        new Template() {
            Authentication authentication = mock( Authentication.class );
            HttpServletResponse response = mock( HttpServletResponse.class );

            @Override
            protected void given() throws Exception {
                setField( listener, "response", response );
            }

            @Override
            protected void when() throws Exception {
                listener.onApplicationEvent( new AuthenticationSuccessEvent( authentication ) );
            }

            @Override
            protected void then() throws Exception {
                verify( servletBinder ).bind( response, authentication );
            }
        }.run();
    }

    @Test
    public void doNothingIfEventIsNotAuthenticationSuccess() throws Exception {
        new Template() {
            HttpServletResponse response = mock( HttpServletResponse.class );

            @Override
            protected void given() throws Exception {
                setField( listener, "response", response );
            }

            @Override
            protected void when() throws Exception {
                listener.onApplicationEvent( mock( ApplicationEvent.class ) );
            }

            @Override
            protected void then() throws Exception {
                verifyZeroInteractions( servletBinder );
            }
        }.run();
    }


}