package nz.co.katatech.springboot.security.stateless.config;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Implementation based on EnableOAuth2SsoCondition
 */
public class EnableStatelessSecurityCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome( ConditionContext context,
                                             AnnotatedTypeMetadata metadata ) {
        String[] enablers = context.getBeanFactory()
            .getBeanNamesForAnnotation( EnableStatelessSecurity.class );
        ConditionMessage.Builder message = ConditionMessage
            .forCondition( "@EnableStatelessSecurity Condition" );
        for ( String name : enablers ) {
            if ( context.getBeanFactory().isTypeMatch( name,
                WebSecurityConfigurerAdapter.class ) ) {
                return ConditionOutcome.match( message
                    .found( "@EnableStatelessSecurity annotation on WebSecurityConfigurerAdapter" )
                    .items( name ) );
            }
        }
        return ConditionOutcome.noMatch( message.didNotFind(
            "@EnableStatelessSecurity annotation " + "on any WebSecurityConfigurerAdapter" )
            .atAll() );
    }

}
