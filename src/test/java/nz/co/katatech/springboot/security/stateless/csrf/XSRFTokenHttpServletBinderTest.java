package nz.co.katatech.springboot.security.stateless.csrf;

import com.google.common.collect.ImmutableList;
import nz.co.katatech.springboot.security.stateless.HttpServletBinder;
import nz.co.testamation.testcommon.fixture.SomeFixture;
import nz.co.testamation.testcommon.template.MockitoTestTemplate;
import org.junit.Test;
import org.springframework.security.core.Authentication;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

public class XSRFTokenHttpServletBinderTest {

    abstract class Template extends MockitoTestTemplate {
        HttpServletBinder delegate = mock( HttpServletBinder.class );
        XSRFTokenHttpServletBinder binder = new XSRFTokenHttpServletBinder( delegate );

        HttpServletRequest request = mock( HttpServletRequest.class );
        HttpServletResponse response = mock( HttpServletResponse.class );
        Authentication authentication = mock( Authentication.class );

        List<String> updateMethods = ImmutableList.of( "POST", "PATCH", "PUT", "DELETE" );

        public static final String XSRF_TOKEN_COOKIE_NAME = "XSRF-TOKEN";
        public static final String XSRF_TOKEN_HEADER_NAME = "X-XSRF-TOKEN";

        Cookie createCookie( String key, String value ) {
            Cookie cookie = mock( Cookie.class );
            given( cookie.getValue() ).thenReturn( value );
            given( cookie.getName() ).thenReturn( key );
            return cookie;
        }

    }

    @Test
    public void ifMatchingCookieAndHeaderThenCallDelegate() throws Exception {
        new Template() {
            Authentication actual;
            String tokenValue = SomeFixture.someString();
            Cookie[] cookies = new Cookie[]{createCookie( XSRF_TOKEN_COOKIE_NAME, tokenValue )};

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                given( request.getCookies() ).thenReturn( cookies );
                given( request.getHeader( XSRF_TOKEN_HEADER_NAME ) ).thenReturn( tokenValue );
                given( delegate.retrieve( request ) ).thenReturn( authentication );

            }

            @Override
            protected void when() throws Exception {
                actual = binder.retrieve( request );
            }

            @Override
            protected void then() throws Exception {
                assertThat( actual, equalTo( authentication ) );
            }
        }.run();
    }

    @Test
    public void returnNullIfCookieAndHeaderValueDoesNotMatch() throws Exception {
        new Template() {
            Authentication actual;
            String headerValue = SomeFixture.someString();
            String cookieValue = SomeFixture.someString();
            Cookie[] cookies = new Cookie[]{createCookie( XSRF_TOKEN_COOKIE_NAME, cookieValue )};

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                given( request.getCookies() ).thenReturn( cookies );
                given( request.getHeader( XSRF_TOKEN_HEADER_NAME ) ).thenReturn( headerValue );
                given( delegate.retrieve( request ) ).thenReturn( authentication );

            }

            @Override
            protected void when() throws Exception {
                actual = binder.retrieve( request );
            }

            @Override
            protected void then() throws Exception {
                verifyZeroInteractions( delegate );
                assertThat( actual, equalTo( null ) );
            }
        }.run();
    }

    @Test
    public void ifNoXSRFTokenCookieThenReturnNull() throws Exception {
        new Template() {
            Authentication actual;
            String tokenValue = SomeFixture.someString();

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                Cookie[] cookies = new Cookie[]{createCookie( SomeFixture.someString(), tokenValue )};
                given( request.getCookies() ).thenReturn( cookies );
                given( request.getHeader( XSRF_TOKEN_HEADER_NAME ) ).thenReturn( tokenValue );

            }

            @Override
            protected void when() throws Exception {
                actual = binder.retrieve( request );
            }

            @Override
            protected void then() throws Exception {
                verifyZeroInteractions( delegate );
                assertThat( actual, equalTo( null ) );
            }
        }.run();
    }

    @Test
    public void ifNoXSRFHeaderThenReturnNull() throws Exception {
        new Template() {
            Authentication actual;
            String tokenValue = SomeFixture.someString();

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                Cookie[] cookies = new Cookie[]{createCookie( XSRF_TOKEN_COOKIE_NAME, tokenValue )};
                given( request.getCookies() ).thenReturn( cookies );
                given( request.getHeader( XSRF_TOKEN_HEADER_NAME ) ).thenReturn( null );

            }

            @Override
            protected void when() throws Exception {
                actual = binder.retrieve( request );
            }

            @Override
            protected void then() throws Exception {
                verifyZeroInteractions( delegate );
                assertThat( actual, equalTo( null ) );
            }
        }.run();
    }


    @Test
    public void retrievesCallDelegateIfNotUpdateMethod() throws Exception {
        new Template() {
            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someString() );
                given( delegate.retrieve( request ) ).thenReturn( authentication );
            }

            @Override
            protected void when() throws Exception {
                actual = binder.retrieve( request );
            }

            @Override
            protected void then() throws Exception {
                verify( delegate ).retrieve( request );
                assertThat( actual, equalTo( authentication ) );
            }
        }.run();
    }

    @Test
    public void bindSimplyCallDelegate() throws Exception {
        new Template() {


            @Override
            protected void when() throws Exception {
                binder.bind( response, authentication );
            }

            @Override
            protected void then() throws Exception {
                verify( delegate ).bind( response, authentication );
            }
        }.run();
    }


}