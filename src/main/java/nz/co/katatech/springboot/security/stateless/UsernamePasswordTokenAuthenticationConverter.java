package nz.co.katatech.springboot.security.stateless;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class UsernamePasswordTokenAuthenticationConverter implements AuthenticationConverter<String> {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public static class UserAndRoles {
        private final @JsonProperty String user;
        private final @JsonProperty List<String> roles;

        private UserAndRoles( @JsonProperty( "user" ) String user, @JsonProperty( "roles" ) List<String> roles ) {
            this.user = user;
            this.roles = roles;
        }
    }

    @Override
    public String convert( Authentication authentication ) {
        try {
            return objectMapper.writeValueAsString( new UserAndRoles(
                String.valueOf( authentication.getPrincipal() ),
                authentication.getAuthorities().stream().map( GrantedAuthority::getAuthority ).collect( Collectors.toList() )
            ) );
        } catch ( JsonProcessingException e ) {
            throw new RuntimeException( e );
        }

    }

    @Override
    public Authentication convert( String token ) {
        try {
            UserAndRoles userAndRoles = objectMapper.readValue( token, UserAndRoles.class );
            return new UsernamePasswordAuthenticationToken(
                userAndRoles.user,
                "N/A",
                userAndRoles.roles.stream().map( SimpleGrantedAuthority::new ).collect( Collectors.toList() )
            );

        } catch ( IOException e ) {
            throw new RuntimeException( e );
        }

    }
}

