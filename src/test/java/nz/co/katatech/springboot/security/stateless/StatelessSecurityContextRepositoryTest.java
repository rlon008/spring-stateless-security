package nz.co.katatech.springboot.security.stateless;

import nz.co.testamation.testcommon.template.MockitoTestTemplate;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class StatelessSecurityContextRepositoryTest {
    abstract class Template extends MockitoTestTemplate {

        HttpServletBinder<Authentication> servletBinder = mock( HttpServletBinder.class );
        StatelessSecurityContextRepository repository = new StatelessSecurityContextRepository( servletBinder );

        HttpServletResponse response = mock( HttpServletResponse.class );
        HttpServletRequest request = mock( HttpServletRequest.class );
    }

    @Test
    public void saveDoNothing() throws Exception {
        new Template() {

            SecurityContext securityContext = mock( SecurityContext.class );

            @Override
            protected void when() throws Exception {
                repository.saveContext( securityContext, request, response );
            }

            @Override
            protected void then() throws Exception {
                verifyZeroInteractions( request, response, securityContext );
            }
        }.run();
    }

    @Test
    public void containsContextAlwaysReturnFalse() throws Exception {
        new Template() {
            boolean actual;


            @Override
            protected void when() throws Exception {
                actual = repository.containsContext( request );
            }

            @Override
            protected void then() throws Exception {
                verifyZeroInteractions( request );
                assertThat( actual, equalTo( false ) );
            }
        }.run();
    }

    @Test
    public void loadContextHappyDay() throws Exception {
        new Template() {
            SecurityContext actual;
            Authentication authentication = mock( Authentication.class );

            @Override
            protected void given() throws Exception {
                given( servletBinder.retrieve( request ) ).thenReturn( authentication );
            }

            @Override
            protected void when() throws Exception {
                actual = repository.loadContext( new HttpRequestResponseHolder( request, response ) );
            }

            @Override
            protected void then() throws Exception {
                assertThat( actual.getAuthentication(), equalTo( authentication ) );
            }
        }.run();
    }


}