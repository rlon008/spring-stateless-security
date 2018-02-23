package nz.co.katatech.springboot.security.stateless;

import nz.co.testamation.testcommon.fixture.SomeFixture;
import nz.co.testamation.testcommon.template.MockitoTestTemplate;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class XAuthTokenHttpServletBinderTest {

    abstract class Template extends MockitoTestTemplate {
        AuthenticationConverter<String> authenticationConverter = mock( AuthenticationConverter.class );
        TokenParser<String> tokenParser = mock( TokenParser.class );
        XAuthTokenHttpServletBinder xauthTokenBinder = new XAuthTokenHttpServletBinder( tokenParser, authenticationConverter );
        Cookie cookie1 = mock( Cookie.class );
        Cookie cookie2 = mock( Cookie.class );
        String cookieValue = SomeFixture.someString();
    }

    @Test
    public void retrieveTheRightCookieAndCovertToAuthentication() throws Exception {
        new Template() {
            HttpServletRequest request = mock( HttpServletRequest.class );


            String parsedToken = SomeFixture.someString();
            Authentication authentication = mock( Authentication.class );
            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getCookies() ).thenReturn( new Cookie[]{cookie1, cookie2} );
                given( cookie1.getName() ).thenReturn( SomeFixture.someString() );
                given( cookie2.getName() ).thenReturn( HttpServletBinder.X_AUTH_TOKEN );

                given( cookie2.getValue() ).thenReturn( cookieValue );
                given( tokenParser.parse( cookieValue ) ).thenReturn( parsedToken );
                given( authenticationConverter.convert( parsedToken ) ).thenReturn( authentication );
            }

            @Override
            protected void when() throws Exception {
                actual = xauthTokenBinder.retrieve( request );
            }

            @Override
            protected void then() throws Exception {
                assertThat( actual, equalTo( authentication ) );
            }
        }.run();
    }

    @Test
    public void retrieveHandleNull() throws Exception {
        new Template() {
            HttpServletRequest request = mock( HttpServletRequest.class );
            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getCookies() ).thenReturn( null );
            }

            @Override
            protected void when() throws Exception {
                actual = xauthTokenBinder.retrieve( request );
            }

            @Override
            protected void then() throws Exception {
                assertThat( actual, equalTo( null ) );
            }
        }.run();
    }

    @Test
    public void retrieveHandleNoMatchingCookie() throws Exception {
        new Template() {
            HttpServletRequest request = mock( HttpServletRequest.class );
            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getCookies() ).thenReturn( new Cookie[]{cookie1, cookie2} );
                given( cookie1.getName() ).thenReturn( SomeFixture.someString() );
            }

            @Override
            protected void when() throws Exception {
                actual = xauthTokenBinder.retrieve( request );
            }

            @Override
            protected void then() throws Exception {
                assertThat( actual, equalTo( null ) );
            }
        }.run();
    }

    @Test
    public void bindWriteCorrectCookie() throws Exception {
        new Template() {
            HttpServletResponse response = mock( HttpServletResponse.class );
            Authentication authentication = mock( Authentication.class );
            String xAuthToken = SomeFixture.someString();

            @Override
            protected void given() throws Exception {
                String authenticationToken = SomeFixture.someString();
                given( authenticationConverter.convert( authentication ) ).thenReturn( authenticationToken );
                given( tokenParser.generate( authenticationToken ) ).thenReturn( xAuthToken );
            }

            @Override
            protected void when() throws Exception {
                xauthTokenBinder.bind( response, authentication );
            }

            @Override
            protected void then() throws Exception {
                verify(response).addCookie( Mockito.argThat( new TypeSafeMatcher<Cookie>() {
                    @Override
                    public void describeTo( Description description ) {
                        //do nothing
                    }

                    @Override
                    protected boolean matchesSafely( Cookie item ) {
                        return item.getName().equals( HttpServletBinder.X_AUTH_TOKEN ) &&
                            item.getPath().equals( "/" ) &&
                            item.getValue().equals( xAuthToken );
                    }
                }  ) );
            }
        }.run();
    }


}