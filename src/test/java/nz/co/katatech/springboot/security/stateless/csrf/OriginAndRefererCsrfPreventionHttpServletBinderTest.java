package nz.co.katatech.springboot.security.stateless.csrf;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import nz.co.katatech.springboot.security.stateless.HttpServletBinder;
import nz.co.testamation.testcommon.fixture.SomeFixture;
import nz.co.testamation.testcommon.template.MockitoTestTemplate;
import org.junit.Test;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

public class OriginAndRefererCsrfPreventionHttpServletBinderTest {

    abstract class Template extends MockitoTestTemplate {
        String validDomin1 = "http://" + SomeFixture.someString() + "/";
        String validDomin2 = "http://" + SomeFixture.someString() + "/";
        List<String> validDomains = Lists.newArrayList( validDomin1, validDomin2 );
        HttpServletBinder<Authentication> delegate = mock( HttpServletBinder.class );
        OriginAndRefererCsrfPreventionHttpServletBinder binder = new OriginAndRefererCsrfPreventionHttpServletBinder( delegate, validDomains );

        HttpServletRequest request = mock( HttpServletRequest.class );
        HttpServletResponse response = mock( HttpServletResponse.class );
        Authentication authentication = mock( Authentication.class );

        List<String> updateMethods = ImmutableList.of( "POST", "PATCH", "PUT", "DELETE" );
    }

    @Test
    public void bindSimplyCallsDelegage() throws Exception {
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
    public void returnNullIfMethodIsAnUpdateAndOriginIsNotAValidDomain() throws Exception {
        new Template() {
            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                given( request.getHeader( "Origin" ) ).thenReturn( SomeFixture.someString() );
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
    public void callDelegateIfMethodIsAnUpdateAndOriginIsAValidDomain() throws Exception {
        new Template() {
            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                given( request.getHeader( "Origin" ) ).thenReturn( SomeFixture.someValue( validDomin1, validDomin2 ));
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
    public void callDelegateIfMethodIsAnUpdateAndOriginStartsWithValidDomain() throws Exception {
        new Template() {
            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                given( request.getHeader( "Origin" ) ).thenReturn( SomeFixture.someValue( validDomin1, validDomin2 ) + SomeFixture.someString());
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
    public void useReferrerIfOriginIsNotSetValidDomain() throws Exception {
        new Template() {
            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                given( request.getHeader( "Origin" ) ).thenReturn( null );
                given( request.getHeader( "Referer" ) ).thenReturn( SomeFixture.someValue( validDomin2, validDomin1 ) + "/sdflkjsdflk" );
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
    public void returnNullIfRefererDoesNotMatchValidDomain() throws Exception {
        new Template() {
            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                given( request.getHeader( "Origin" ) ).thenReturn( null );
                given( request.getHeader( "Referer" ) ).thenReturn( SomeFixture.someString() );
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
    public void returnNullIfBothOriginAndRefererAreNotSet() throws Exception {
        new Template() {
            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                given( request.getHeader( "Origin" ) ).thenReturn( null );
                given( request.getHeader( "Referer" ) ).thenReturn( null );
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
    public void retrieveCallsDelegateIfNoValidDomainsConfigured() throws Exception {
        new Template() {
            OriginAndRefererCsrfPreventionHttpServletBinder binder = new OriginAndRefererCsrfPreventionHttpServletBinder(
                delegate, Lists.newArrayList()
            );

            Authentication actual;


            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
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
    public void handleTrailingSlashCorrectly() throws Exception {
        new Template() {
            String host = SomeFixture.someString();

            OriginAndRefererCsrfPreventionHttpServletBinder binder = new OriginAndRefererCsrfPreventionHttpServletBinder(
                delegate, Lists.newArrayList("http://" + host )
            );

            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                given( request.getHeader( "Origin" ) ).thenReturn( null );
                given( request.getHeader( "Referer" ) ).thenReturn( "http://" + host + ".evil-domain.com" );
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
    public void handleTrailingSlashCorrectlyForOrigin() throws Exception {
        new Template() {
            String host = SomeFixture.someString();

            OriginAndRefererCsrfPreventionHttpServletBinder binder = new OriginAndRefererCsrfPreventionHttpServletBinder(
                delegate, Lists.newArrayList("http://" + host + "/" )
            );

            Authentication actual;

            @Override
            protected void given() throws Exception {
                given( request.getMethod() ).thenReturn( SomeFixture.someValue( updateMethods ) );
                given( request.getHeader( "Origin" ) ).thenReturn( "http://" + host  );
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



}