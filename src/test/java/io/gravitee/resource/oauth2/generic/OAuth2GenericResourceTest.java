/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.oauth2.generic;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.Mockito.lenient;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.common.http.MediaType;
import io.gravitee.el.TemplateEngine;
import io.gravitee.el.spel.context.SecuredResolver;
import io.gravitee.node.api.Node;
import io.gravitee.plugin.configurations.http.HttpClientOptions;
import io.gravitee.plugin.configurations.http.HttpProxyOptions;
import io.gravitee.plugin.configurations.ssl.SslOptions;
import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.oauth2.api.OAuth2ResourceMetadata;
import io.gravitee.resource.oauth2.api.tokenexchange.TokenExchangeRequest;
import io.gravitee.resource.oauth2.api.tokenexchange.TokenExchangeResponse;
import io.gravitee.resource.oauth2.generic.configuration.OAuth2ResourceConfiguration;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.vertx.rxjava3.core.Vertx;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationContext;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@WireMockTest
@ExtendWith({ MockitoExtension.class })
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class OAuth2GenericResourceTest {

    private static TemplateEngine templateEngine;

    @Mock
    private ApplicationContext applicationContext;

    private OAuth2ResourceConfiguration configuration;

    @Mock
    private Node node;

    private OAuth2GenericResource resource;

    @BeforeAll
    static void init() {
        SecuredResolver.initialize(null);
        templateEngine = TemplateEngine.templateEngine();
    }

    @BeforeEach
    void before() throws Exception {
        resource = new OAuth2GenericResource();
        resource.setApplicationContext(applicationContext);
        resource.setDeploymentContext(new TestDeploymentContext(templateEngine));
        configuration = new OAuth2ResourceConfiguration();
        Field configurationField = AbstractConfigurableResource.class.getDeclaredField("configuration");
        configurationField.setAccessible(true);
        configurationField.set(resource, configuration);

        lenient().when(applicationContext.getBean(Node.class)).thenReturn(node);
        lenient().when(applicationContext.getBean(Vertx.class)).thenReturn(Vertx.vertx());
    }

    @Test
    void should_call_with_header(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());
        configuration.setTokenIsSuppliedByHttpHeader(true);
        configuration.setTokenHeaderName(HttpHeaderNames.AUTHORIZATION.toString());

        resource.doStart();

        AtomicBoolean check = new AtomicBoolean();
        resource.introspect(accessToken, oAuth2Response -> check.set(true));

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);

        verify(
            postRequestedFor(urlPathEqualTo("/oauth/introspect")).withHeader(HttpHeaderNames.AUTHORIZATION.toString(), equalTo(accessToken))
        );
    }

    @Test
    void should_call_with_authorization_server_url(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        AtomicBoolean check = new AtomicBoolean();

        configuration.setAuthorizationServerUrl("http://localhost:" + wireMockRuntimeInfo.getHttpPort());
        configuration.setIntrospectionEndpoint("/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());
        configuration.setTokenIsSuppliedByHttpHeader(true);
        configuration.setTokenHeaderName(HttpHeaderNames.AUTHORIZATION.toString());

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> check.set(true));

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);

        verify(
            postRequestedFor(urlPathEqualTo("/oauth/introspect")).withHeader(HttpHeaderNames.AUTHORIZATION.toString(), equalTo(accessToken))
        );
    }

    @Test
    void should_call_with_query_param(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(
            post(urlPathEqualTo("/oauth/introspect"))
                .withQueryParam("token", equalTo(accessToken))
                .willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}"))
        );

        AtomicBoolean check = new AtomicBoolean();

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());
        configuration.setTokenIsSuppliedByQueryParam(true);
        configuration.setTokenQueryParamName("token");

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> check.set(true));

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);

        verify(postRequestedFor(urlPathEqualTo(("/oauth/introspect"))).withQueryParam("token", equalTo(accessToken)));
    }

    @Test
    void should_call_with_form_body(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        AtomicBoolean check = new AtomicBoolean();

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());
        configuration.setTokenIsSuppliedByFormUrlEncoded(true);
        configuration.setTokenFormUrlEncodedName("token");

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> check.set(true));

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);

        verify(
            postRequestedFor(urlEqualTo("/oauth/introspect"))
                .withHeader(HttpHeaderNames.CONTENT_TYPE.toString(), equalTo(MediaType.APPLICATION_FORM_URLENCODED))
                .withRequestBody(equalTo("token=" + accessToken))
        );
    }

    @Test
    void should_validate_access_token(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        AtomicBoolean check = new AtomicBoolean();

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect("xxxx-xxxx-xxxx-xxxx", oAuth2Response -> {
            assertThat(oAuth2Response.isSuccess()).isTrue();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_not_validate_access_token(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(401)));

        AtomicBoolean check = new AtomicBoolean();

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect("xxxx-xxxx-xxxx-xxxx", oAuth2Response -> {
            assertThat(oAuth2Response.isSuccess()).isFalse();
            assertThat(oAuth2Response.getPayload()).isEqualTo("An error occurs while checking OAuth2 token");
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_not_validate_access_token_not_active(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"active\": \"false\"}")));

        AtomicBoolean check = new AtomicBoolean();

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect("xxxx-xxxx-xxxx-xxxx", oAuth2Response -> {
            assertThat(oAuth2Response.isSuccess()).isFalse();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_get_user_info(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(
            get(urlEqualTo("/userinfo")).willReturn(
                aResponse().withStatus(200).withBody("{\"sub\": \"248289761001\", \"name\": \"Jane Doe\", \"given_name\": \"Jane\"}")
            )
        );

        AtomicBoolean check = new AtomicBoolean();

        configuration.setAuthorizationServerUrl("http://localhost:" + wireMockRuntimeInfo.getHttpPort());
        configuration.setUserInfoEndpoint("/userinfo");
        configuration.setUserInfoEndpointMethod(HttpMethod.GET.name());

        resource.doStart();

        resource.userInfo("xxxx-xxxx-xxxx-xxxx", userInfoResponse -> {
            assertThat(userInfoResponse.isSuccess()).isTrue();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_post_user_info(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(
            post(urlEqualTo("/userinfo")).willReturn(
                aResponse().withStatus(200).withBody("{\"sub\": \"248289761001\", \"name\": \"Jane Doe\", \"given_name\": \"Jane\"}")
            )
        );

        AtomicBoolean check = new AtomicBoolean();

        configuration.setAuthorizationServerUrl("http://localhost:" + wireMockRuntimeInfo.getHttpPort());
        configuration.setUserInfoEndpoint("/userinfo");
        configuration.setUserInfoEndpointMethod(HttpMethod.POST.name());

        resource.doStart();

        resource.userInfo("xxxx-xxxx-xxxx-xxxx", userInfoResponse -> {
            assertThat(userInfoResponse.isSuccess()).isTrue();
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_not_get_user_info(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(get(urlEqualTo("/userinfo")).willReturn(aResponse().withStatus(401)));

        AtomicBoolean check = new AtomicBoolean();

        configuration.setAuthorizationServerUrl("http://localhost:" + wireMockRuntimeInfo.getHttpPort());
        configuration.setUserInfoEndpoint("/userinfo");
        configuration.setUserInfoEndpointMethod(HttpMethod.GET.name());

        resource.doStart();

        resource.userInfo("xxxx-xxxx-xxxx-xxxx", userInfoResponse -> {
            assertThat(userInfoResponse.isSuccess()).isFalse();
            assertThat(userInfoResponse.getPayload()).isEqualTo("An error occurs while getting userinfo from access token");
            check.set(true);
        });

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_get_default_user_claim() {
        assertThat(resource.getUserClaim()).isEqualTo("sub");
    }

    @ParameterizedTest
    @ValueSource(strings = { "https://some.keycloak.com", "https://some.keycloak.com/" })
    public void testGetProtectedResourceMetadata(String authorizationServerUrl) throws NoSuchFieldException, IllegalAccessException {
        OAuth2GenericResource resource = new OAuth2GenericResource();
        OAuth2ResourceConfiguration configuration = new OAuth2ResourceConfiguration();
        configuration.setAuthorizationServerMetadataEndpoint("/realms/myrealm/.well-known/oauth-authorization-server");
        configuration.setAuthorizationServerUrl(authorizationServerUrl);
        resource.setConfiguration(configuration);
        OAuth2ResourceMetadata resourceMetadata = resource.getProtectedResourceMetadata("https://backend.com", List.of());
        assertAll(
            () -> assertThat(resourceMetadata.protectedResourceUri()).isEqualTo("https://backend.com"),
            () -> assertThat(resourceMetadata.authorizationServers().get(0)).isEqualTo("https://some.keycloak.com/realms/myrealm"),
            () -> assertThat(resourceMetadata.authorizationServers().size()).isEqualTo(1),
            () -> assertThat(resourceMetadata.scopesSupported()).isEmpty()
        );
    }

    @ParameterizedTest
    @ValueSource(strings = { "https://some.keycloak.com", "https://some.keycloak.com/" })
    public void testGetProtectedResourceMetadata_with_scopes_supported(String authorizationServerUrl) {
        OAuth2GenericResource resource = new OAuth2GenericResource();
        OAuth2ResourceConfiguration configuration = new OAuth2ResourceConfiguration();
        configuration.setAuthorizationServerMetadataEndpoint("/realms/myrealm/.well-known/oauth-authorization-server");
        configuration.setAuthorizationServerUrl(authorizationServerUrl);
        resource.setConfiguration(configuration);
        List<String> scopesSupported = List.of("read", "write", "admin");
        OAuth2ResourceMetadata resourceMetadata = resource.getProtectedResourceMetadata("https://backend.com", scopesSupported);
        assertAll(
            () -> assertThat(resourceMetadata.protectedResourceUri()).isEqualTo("https://backend.com"),
            () -> assertThat(resourceMetadata.authorizationServers().get(0)).isEqualTo("https://some.keycloak.com/realms/myrealm"),
            () -> assertThat(resourceMetadata.authorizationServers().size()).isEqualTo(1),
            () -> assertThat(resourceMetadata.scopesSupported()).containsExactly("read", "write", "admin")
        );
    }

    @Test
    void should_exchange_token_with_basic_client_authentication(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(
            post(urlEqualTo("/oauth/token")).willReturn(
                aResponse()
                    .withStatus(200)
                    .withBody(
                        "{\"access_token\": \"exchanged-token\", \"issued_token_type\": \"urn:ietf:params:oauth:token-type:access_token\", \"token_type\": \"Bearer\", \"expires_in\": 3600, \"scope\": \"read\"}"
                    )
            )
        );

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());
        configuration.setTokenExchangeEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/token");
        configuration.setClientId("my-client");
        configuration.setClientSecret("my-secret");
        configuration.setUseClientAuthorizationHeader(true);
        configuration.setClientAuthorizationHeaderName("Authorization");
        configuration.setClientAuthorizationHeaderScheme("Basic");

        resource.doStart();

        AtomicReference<TokenExchangeResponse> result = new AtomicReference<>();
        resource.tokenExchange(
            TokenExchangeRequest.builder("subject-token", TokenExchangeRequest.TOKEN_TYPE_ACCESS_TOKEN).audience("upstream-mcp").build(),
            result::set
        );

        Awaitility.await()
            .atMost(10, TimeUnit.SECONDS)
            .until(() -> result.get() != null);

        assertAll(
            () -> assertThat(result.get().isSuccess()).isTrue(),
            () -> assertThat(result.get().getAccessToken()).isEqualTo("exchanged-token"),
            () -> assertThat(result.get().getIssuedTokenType()).isEqualTo("urn:ietf:params:oauth:token-type:access_token"),
            () -> assertThat(result.get().getTokenType()).isEqualTo("Bearer"),
            () -> assertThat(result.get().getExpiresIn()).isEqualTo(3600L),
            () -> assertThat(result.get().getScope()).isEqualTo("read")
        );

        verify(
            postRequestedFor(urlPathEqualTo("/oauth/token"))
                .withHeader(
                    "Authorization",
                    equalTo("Basic " + Base64.getEncoder().encodeToString("my-client:my-secret".getBytes(StandardCharsets.UTF_8)))
                )
                .withRequestBody(containing("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"))
                .withRequestBody(containing("subject_token=subject-token"))
                .withRequestBody(containing("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"))
                .withRequestBody(containing("audience=upstream-mcp"))
        );
    }

    @Test
    void should_exchange_token_with_client_credentials_in_body(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(
            post(urlEqualTo("/oauth/token")).willReturn(
                aResponse()
                    .withStatus(200)
                    .withBody(
                        "{\"access_token\": \"exchanged-token\", \"issued_token_type\": \"urn:ietf:params:oauth:token-type:access_token\", \"token_type\": \"Bearer\"}"
                    )
            )
        );

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());
        configuration.setTokenExchangeEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/token");
        configuration.setClientId("my-client");
        configuration.setClientSecret("my-secret");
        configuration.setUseClientAuthorizationHeader(false);

        resource.doStart();

        AtomicReference<TokenExchangeResponse> result = new AtomicReference<>();
        resource.tokenExchange(
            TokenExchangeRequest.builder("subject-token", TokenExchangeRequest.TOKEN_TYPE_ACCESS_TOKEN).build(),
            result::set
        );

        Awaitility.await()
            .atMost(10, TimeUnit.SECONDS)
            .until(() -> result.get() != null);

        assertThat(result.get().isSuccess()).isTrue();

        verify(
            postRequestedFor(urlPathEqualTo("/oauth/token"))
                .withRequestBody(containing("client_id=my-client"))
                .withRequestBody(containing("client_secret=my-secret"))
        );
    }

    @Test
    void should_fail_token_exchange_when_endpoint_returns_an_error(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(post(urlEqualTo("/oauth/token")).willReturn(aResponse().withStatus(400).withBody("{\"error\": \"invalid_grant\"}")));

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());
        configuration.setTokenExchangeEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/token");

        resource.doStart();

        AtomicReference<TokenExchangeResponse> result = new AtomicReference<>();
        resource.tokenExchange(
            TokenExchangeRequest.builder("subject-token", TokenExchangeRequest.TOKEN_TYPE_ACCESS_TOKEN).build(),
            result::set
        );

        Awaitility.await()
            .atMost(10, TimeUnit.SECONDS)
            .until(() -> result.get() != null);

        assertAll(() -> assertThat(result.get().isSuccess()).isFalse(), () -> assertThat(result.get().getThrowable()).isNotNull());
    }

    @Test
    void should_fail_token_exchange_when_subject_token_is_missing(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());
        configuration.setTokenExchangeEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/token");

        resource.doStart();

        AtomicReference<TokenExchangeResponse> result = new AtomicReference<>();
        resource.tokenExchange(TokenExchangeRequest.builder(null, TokenExchangeRequest.TOKEN_TYPE_ACCESS_TOKEN).build(), result::set);

        Awaitility.await()
            .atMost(10, TimeUnit.SECONDS)
            .until(() -> result.get() != null);

        assertAll(
            () -> assertThat(result.get().isSuccess()).isFalse(),
            () -> assertThat(result.get().getThrowable()).hasMessageContaining("subject_token is required")
        );
    }

    @Test
    void should_fail_token_exchange_when_token_endpoint_is_not_configured(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());

        resource.doStart();

        AtomicReference<TokenExchangeResponse> result = new AtomicReference<>();
        resource.tokenExchange(
            TokenExchangeRequest.builder("subject-token", TokenExchangeRequest.TOKEN_TYPE_ACCESS_TOKEN).build(),
            result::set
        );

        Awaitility.await()
            .atMost(10, TimeUnit.SECONDS)
            .until(() -> result.get() != null);

        assertAll(
            () -> assertThat(result.get().isSuccess()).isFalse(),
            () -> assertThat(result.get().getThrowable()).hasMessageContaining("tokenExchangeEndpoint is not configured")
        );
    }
}
