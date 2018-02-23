package nz.co.katatech.springboot.security.stateless;

import org.springframework.security.core.Authentication;

public interface AuthenticationConverter<T> {

    T convert( Authentication authentication );

    Authentication convert( T token );
}