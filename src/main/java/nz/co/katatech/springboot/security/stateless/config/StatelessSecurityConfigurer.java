package nz.co.katatech.springboot.security.stateless.config;

import nz.co.katatech.springboot.security.stateless.HttpServletBinder;
import nz.co.katatech.springboot.security.stateless.StatelessSecurityContextRepository;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class StatelessSecurityConfigurer {

    private final StatelessSecurityContextRepository repository;

    public StatelessSecurityConfigurer( StatelessSecurityContextRepository repository ) {
        this.repository = repository;
    }

    public HttpSecurity configure( HttpSecurity http ) throws Exception {
        http.csrf().disable()
            .securityContext().securityContextRepository( repository )
            .and().logout().deleteCookies( HttpServletBinder.X_AUTH_TOKEN );
        return http;
    }
}
