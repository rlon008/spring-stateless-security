package nz.co.katatech.springboot.security.stateless.config;


import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * @author Ratha Long
 */
@Target( ElementType.TYPE )
@Retention( RetentionPolicy.RUNTIME )
@Documented
@Import( {StatelessSecurityConfiguration.class} )
public @interface EnableStatelessSecurity {
}
