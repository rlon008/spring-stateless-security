package nz.co.katatech.springboot.security.stateless;

import com.google.common.collect.Lists;
import nz.co.testamation.testcommon.fixture.SomeFixture;
import nz.co.testamation.testcommon.template.MockitoTestTemplate;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;

public class UsernamePasswordTokenAuthenticationConverterTest {

    abstract class Template extends MockitoTestTemplate {
        UsernamePasswordTokenAuthenticationConverter converter = new UsernamePasswordTokenAuthenticationConverter();
        String user = SomeFixture.someString();
        String role1 = SomeFixture.someString();
        String role2 = SomeFixture.someString();
        String jsonString = String.format(
            "{\"user\":\"%s\",\"roles\":[\"%s\",\"%s\"]}",
            user, role1, role2
        );

        ArrayList<SimpleGrantedAuthority> authorities = Lists.newArrayList(
            new SimpleGrantedAuthority( role1 ), new SimpleGrantedAuthority( role2 )
        );
    }

    @Test
    public void convertAuthenticationToStringTokenCorrectly() throws Exception {
        new Template() {

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken( user, "N/A", authorities );
            String actual;

            @Override
            protected void when() throws Exception {
                actual = converter.convert( authentication );
            }

            @Override
            protected void then() throws Exception {
                assertThat( actual, equalTo( jsonString ) );
            }
        }.run();
    }

    @Test
    public void convertTokenToAuthenticationCorrectly() throws Exception {
        new Template() {

            Authentication actual;

            @Override
            protected void when() throws Exception {
                actual = converter.convert( jsonString );
            }

            @Override
            protected void then() throws Exception {
                assertThat( actual.getPrincipal(), equalTo( user ) );
                assertThat( actual.getCredentials(), equalTo( "N/A" ) );
                assertThat( actual.isAuthenticated(), equalTo( true ) );
                assertThat( actual.getAuthorities(), equalTo( Lists.newArrayList(
                    new SimpleGrantedAuthority( role1 ), new SimpleGrantedAuthority( role2 )
                ) ) );
            }
        }.run();
    }


}