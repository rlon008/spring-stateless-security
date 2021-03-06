package nz.co.katatech.springboot.security.stateless.oauth;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoRestTemplateCustomizer;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;

import java.util.Arrays;

public class DisableStateRestTemplateCustomizer implements UserInfoRestTemplateCustomizer {

    @Override
    public void customize( OAuth2RestTemplate template ) {

        AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain( Arrays.asList(
            new IgnoreStateParamAuthorizationCodeAccessTokenProvider(),  //Customised AuthorizationCodeAccessTokenProvider
            new ImplicitAccessTokenProvider(),
            new ResourceOwnerPasswordAccessTokenProvider(),
            new ClientCredentialsAccessTokenProvider()
        ) );

        template.setAccessTokenProvider( accessTokenProvider );
    }
}
