package nz.co.katatech.springboot.security.stateless;

import io.jsonwebtoken.*;
import nz.co.testamation.testcommon.fixture.SomeFixture;
import nz.co.testamation.testcommon.template.MockitoTestTemplate;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.Date;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

public class JwtTokenParserTest {

    abstract class Template extends MockitoTestTemplate {

        JwtBuilder jwtBuilder = mock( JwtBuilder.class );
        JwtParser jwtParser = mock( JwtParser.class );
        String secret = SomeFixture.someString();
        JwtTokenParser parser = new JwtTokenParser( secret, jwtBuilder, jwtParser, SomeFixture.somePositiveInt() );

    }

    @Test
    public void generateHappyDay() throws Exception {
        new Template() {
            String subject = SomeFixture.someString();
            String token = SomeFixture.someString();
            String actual;

            @Override
            protected void given() throws Exception {
                given( jwtBuilder.setSubject( subject ) ).thenReturn( jwtBuilder );
                given( jwtBuilder.signWith( SignatureAlgorithm.HS512, secret ) ).thenReturn( jwtBuilder );
                given( jwtBuilder.compact() ).thenReturn( token );
            }

            @Override
            protected void when() throws Exception {
                actual = parser.generate( subject );
            }

            @Override
            protected void then() throws Exception {
                assertThat( actual, equalTo( token ) );
                verifyInOrder( jwtBuilder ).setExpiration( Mockito.any( Date.class ) );
                verifyInOrder( jwtBuilder ).setSubject( subject );
                verifyInOrder( jwtBuilder ).signWith( SignatureAlgorithm.HS512, secret );
                verifyInOrder( jwtBuilder ).compact();
            }

        }.run();

    }

    @Test
    public void parseHappyDay() throws Exception {
        new Template() {
            String parsedString = SomeFixture.someString();
            String token = SomeFixture.someString();
            Claims claims = mock( Claims.class );
            Jws<Claims> jws = mock( Jws.class );


            String actual;

            @Override
            protected void given() throws Exception {
                given( jwtParser.setSigningKey( secret ) ).thenReturn( jwtParser );
                given( jwtParser.parseClaimsJws( token ) ).thenReturn( jws );
                given( jws.getBody() ).thenReturn( claims );
                given( claims.getSubject() ).thenReturn( parsedString );
            }

            @Override
            protected void when() throws Exception {
                actual = parser.parse( token );
            }

            @Override
            protected void then() throws Exception {
                assertThat( actual, equalTo( parsedString ) );
                verifyInOrder( jwtParser ).setSigningKey( secret );
                verifyInOrder( jwtParser ).parseClaimsJws( token );
            }

        }.run();

    }

    @Test
    public void blackBoxTest() throws Exception {
        JwtTokenParser parser = new JwtTokenParser( "1&F%21s-MMjs1fnf123", 10 );
        String email = SomeFixture.someEmail();
        String token = parser.generate( email );
        assertThat( email, not( equalTo( token ) ) );
        assertThat( email, equalTo( parser.parse( token ) ) );
    }

    @Test(expected = SignatureException.class)
    public void tokenGeneratedWithDifferentKeyCannotBeParsed() throws Exception {
        String someString = SomeFixture.someString();

        JwtTokenParser otherParser = new JwtTokenParser( "sdfkjsd m,n2m3n12mmn SIDF! ", 10 );
        String token = otherParser.generate( someString );

        JwtTokenParser parser = new JwtTokenParser( "1&F%21s-MMjs1fnf123", 10 );
        parser.parse( token );
    }


    @Test
    public void givenEnoughTimeElapsedGenerateWillGenerateNewToken() throws Exception {
        JwtTokenParser parser = new JwtTokenParser( "1&F%21s-MMjs1fnf123", 10 );
        String email = SomeFixture.someEmail();
        String token1 = parser.generate( email );
        Thread.sleep( 1000 );
        String token2 = parser.generate( email );
        assertThat( token1, not( equalTo( token2 ) ) );
    }

    @Test( expected = ExpiredJwtException.class )
    public void ifTokenExpireThenThrowException() throws Exception {
        JwtTokenParser parser = new JwtTokenParser( "1&F%21s-MMjs1fnf123", 1 );
        String email = SomeFixture.someEmail();
        String token = parser.generate( email );
        Thread.sleep( 1500 );
        parser.parse( token );
    }


}