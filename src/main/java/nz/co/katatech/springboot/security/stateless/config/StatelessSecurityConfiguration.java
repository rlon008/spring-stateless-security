package nz.co.katatech.springboot.security.stateless.config;

import nz.co.katatech.springboot.security.stateless.*;
import nz.co.katatech.springboot.security.stateless.csrf.OriginAndRefererCsrfPreventionHttpServletBinder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.util.StringUtils.isEmpty;


@Configuration
@Conditional( EnableStatelessSecurityCondition.class )
public class StatelessSecurityConfiguration {

    @Autowired
    private HttpServletBinder<Authentication> servletBinder;

    @Bean
    public StatelessSecurityConfigurer configurer() {
        return new StatelessSecurityConfigurer( new StatelessSecurityContextRepository( servletBinder ) );
    }


    @Bean
    @ConditionalOnMissingBean( HttpServletBinder.class )
    @Autowired
    public HttpServletBinder<Authentication> servletBinder(
        TokenParser<String> tokenParser,
        AuthenticationConverter<String> authenticationConverter,
        @Value( "${spring.security.stateless.csrf.validDomains:}" ) String domains
    ) {
        return new OriginAndRefererCsrfPreventionHttpServletBinder(
            new XAuthTokenHttpServletBinder( tokenParser, authenticationConverter ),
            toList( domains )
        );
    }

    private List<String> toList( String domains ) {
        return isEmpty( domains ) ? new ArrayList<>() :
            Arrays.asList( domains.split( "," ) ).stream().map( String::trim ).collect( Collectors.toList() );
    }


    @Bean
    @ConditionalOnMissingBean( AuthenticationConverter.class )
    public AuthenticationConverter authConverter() {
        return new UsernamePasswordTokenAuthenticationConverter();
    }

    @Bean
    @ConditionalOnMissingBean( TokenParser.class )
    public TokenParser tokenParser(
        @Value( "${spring.security.stateless.jwt.secret}" ) String secret,
        @Value( "${spring.security.stateless.jwt.expiryInSeconds}" ) long expiryInSeconds
    ) {
        return new JwtTokenParser( secret, expiryInSeconds );
    }

    @Bean
    public StatelessAuthenticationSuccessListener authSuccessListener() {
        return new StatelessAuthenticationSuccessListener( servletBinder );
    }

}
