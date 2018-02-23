package nz.co.katatech.springboot.security.stateless;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

public class JwtTokenParser implements TokenParser<String> {

    private final String secret;
    private final JwtBuilder jwtBuilder;
    private final JwtParser jwtParser;
    private final long tokenExpiryInSeconds;

    public JwtTokenParser( String secret, long tokenExpiryInSeconds ) {
        this(
            secret,
            Jwts.builder(),
            Jwts.parser(),
            tokenExpiryInSeconds
        );
    }

    public JwtTokenParser( String secret, JwtBuilder builder, JwtParser parser, long tokenExpiryInSeconds ) {
        this.secret = secret;
        jwtBuilder = builder;
        jwtParser = parser;
        this.tokenExpiryInSeconds = tokenExpiryInSeconds;
    }


    @Override
    public String generate( String entity ) {
        jwtBuilder.setExpiration( new Date( System.currentTimeMillis() + ( tokenExpiryInSeconds * 1000 ) ) );
        return jwtBuilder.setSubject( entity ).signWith( SignatureAlgorithm.HS512, secret ).compact();
    }

    @Override
    public String parse( String token ) {
        return jwtParser.setSigningKey( secret ).parseClaimsJws( token ).getBody().getSubject();
    }

}