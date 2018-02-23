# spring-stateless-security
##  1) How it works

This library will hook into existing spring security mechanism and do the following:
   i) Replace the HttpSessionSecurityContextRepository with a stateless version (StatelessSecurityContextRepository) that does not save any state to the session.
      This stateless version will reconstruct the Spring SecurityContext from a JWT token written to the cookie X-AUTH-TOKEN
   ii) Add an ApplicationListener that listen for AuthenticationSuccessEvent, extract the authentication and converts it to string representation (JSON by default).
      This string representation is then use as the subject of the JWT Token.  The JWT Token is then written to cookie X-AUTH-TOKEN.




Usage:

Place on your
@EnableStatelessSecurity

Inject StatelessSecurityConfigurer, and call configure method on it.


Example:

@EnableStatelessSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    StatelessSecurityConfigurer statelessSecurityConfigurer;

    @Override
    protected void configure( HttpSecurity http ) throws Exception {
        statelessSecurityConfigurer.configure( http );

        http.antMatchers("/**")
            .authorizeRequests()
            .antMatchers( "/css/**" ).permitAll()
            .anyRequest().authenticated();
            //ETC.....

    }

}

You must supply the following properties in your application, e.g:

spring.security.stateless.jwt.expiryInSeconds=28800

spring.security.stateless.jwt.secret=<Your secret key>


Customising the authentication Object
By default UsernamePasswordTokenAuthenticationConverter is used which will converts Authentication to JSON that has username/roles and vice-versa converts a JSON string to UsernamePasswordAuthenticationToken.
If you want to change this, implements the AuthenticationConverter interface and declare this implementation as a normal bean inside spring context configuration.
If a bean that implements AuthenticationConverter exists in the spring context, this library will use that instead.



## 2) Protection against CSRF
Default configuration is using Origin & Referer checking, which is sufficient for most cases. It might not work however if the user is behind a proxy that
removes the Origin & Referer headers.

You can alternative use



## 3) Using with Spring OAuth2SSO
If you're using Spring OAuth2SSO (E.g. via @EnableOAuth2Sso), you can use the nz.co.katatech.springboot.security.stateless.oauth.DisableStateRestTemplateCustomizer
to disable stateKey checks (which uses http session underneath). All you need to do is define it as a bean in the spring context and spring OAuth2 will take care of the rest.

You might want to ensure you use preEstablishedRedirectURI as well if you have issue with none-matching redirect_uri when requesting for access token.
Here's an example of Okta SSO configuration:

security.oauth2.client.clientAuthenticationScheme=form
security.oauth2.client.scope=openid profile email
security.oauth2.client.clientId=
security.oauth2.client.clientSecret=
security.oauth2.client.userAuthorizationUri=https://<your-company>.oktapreview.com/oauth2/default/v1/authorize
security.oauth2.client.accessTokenUri=https://<your-company>.oktapreview.com/oauth2/default/v1/token
security.oauth2.resource.userInfoUri=https://<your-company>.oktapreview.com/oauth2/default/v1/userinfo
security.oauth2.client.useCurrentUri=false
security.oauth2.client.preEstablishedRedirectUri=https://<your-application-domain>/login

