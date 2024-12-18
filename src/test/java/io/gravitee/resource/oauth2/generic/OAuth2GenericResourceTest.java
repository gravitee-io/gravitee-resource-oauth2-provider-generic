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
import static org.mockito.Mockito.lenient;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.common.http.MediaType;
import io.gravitee.el.TemplateEngine;
import io.gravitee.el.spel.context.SecuredResolver;
import io.gravitee.node.api.Node;
import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.oauth2.generic.configuration.OAuth2ResourceConfiguration;
import io.vertx.core.Vertx;
import java.lang.reflect.Field;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
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

    @Mock
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

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito
            .when(configuration.getIntrospectionEndpoint())
            .thenReturn("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());
        Mockito.when(configuration.isTokenIsSuppliedByHttpHeader()).thenReturn(true);
        Mockito.when(configuration.getTokenHeaderName()).thenReturn(HttpHeaders.AUTHORIZATION);

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> lock.countDown());

        assertThat(lock.await(10000, TimeUnit.MILLISECONDS)).isTrue();

        verify(postRequestedFor(urlPathEqualTo("/oauth/introspect")).withHeader(HttpHeaders.AUTHORIZATION, equalTo(accessToken)));
    }

    @Test
    void should_call_with_authorization_server_url(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getAuthorizationServerUrl()).thenReturn("http://localhost:" + wireMockRuntimeInfo.getHttpPort());
        Mockito.when(configuration.getIntrospectionEndpoint()).thenReturn("/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());
        Mockito.when(configuration.isTokenIsSuppliedByHttpHeader()).thenReturn(true);
        Mockito.when(configuration.getTokenHeaderName()).thenReturn(HttpHeaders.AUTHORIZATION);

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> lock.countDown());

        assertThat(lock.await(10000, TimeUnit.MILLISECONDS)).isTrue();

        verify(postRequestedFor(urlPathEqualTo("/oauth/introspect")).withHeader(HttpHeaders.AUTHORIZATION, equalTo(accessToken)));
    }

    @Test
    void should_call_with_query_param(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(
            post(urlPathEqualTo("/oauth/introspect"))
                .withQueryParam("token", equalTo(accessToken))
                .willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}"))
        );

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito
            .when(configuration.getIntrospectionEndpoint())
            .thenReturn("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());
        Mockito.when(configuration.isTokenIsSuppliedByQueryParam()).thenReturn(true);
        Mockito.when(configuration.getTokenQueryParamName()).thenReturn("token");

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> lock.countDown());

        assertThat(lock.await(10000, TimeUnit.MILLISECONDS)).isTrue();

        verify(postRequestedFor(urlPathEqualTo(("/oauth/introspect"))).withQueryParam("token", equalTo(accessToken)));
    }

    @Test
    void should_call_with_form_body(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito
            .when(configuration.getIntrospectionEndpoint())
            .thenReturn("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());
        Mockito.when(configuration.isTokenIsSuppliedByFormUrlEncoded()).thenReturn(true);
        Mockito.when(configuration.getTokenFormUrlEncodedName()).thenReturn("token");

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> lock.countDown());

        assertThat(lock.await(10000, TimeUnit.MILLISECONDS)).isTrue();

        verify(
            postRequestedFor(urlEqualTo("/oauth/introspect"))
                .withHeader(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_FORM_URLENCODED))
                .withRequestBody(equalTo("token=" + accessToken))
        );
    }

    @Test
    void should_validate_access_token(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito
            .when(configuration.getIntrospectionEndpoint())
            .thenReturn("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect(
            "xxxx-xxxx-xxxx-xxxx",
            oAuth2Response -> {
                assertThat(oAuth2Response.isSuccess()).isTrue();
                lock.countDown();
            }
        );

        assertThat(lock.await(10000, TimeUnit.MILLISECONDS)).isTrue();
    }

    @Test
    void should_not_validate_access_token(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(401)));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito
            .when(configuration.getIntrospectionEndpoint())
            .thenReturn("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect(
            "xxxx-xxxx-xxxx-xxxx",
            oAuth2Response -> {
                assertThat(oAuth2Response.isSuccess()).isFalse();
                assertThat(oAuth2Response.getPayload()).isEqualTo("An error occurs while checking OAuth2 token");
                lock.countDown();
            }
        );

        assertThat(lock.await(10000, TimeUnit.MILLISECONDS)).isTrue();
    }

    @Test
    void should_not_validate_access_token_not_active(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"active\": \"false\"}")));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito
            .when(configuration.getIntrospectionEndpoint())
            .thenReturn("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect(
            "xxxx-xxxx-xxxx-xxxx",
            oAuth2Response -> {
                assertThat(oAuth2Response.isSuccess()).isFalse();
                lock.countDown();
            }
        );

        assertThat(lock.await(10000, TimeUnit.MILLISECONDS)).isTrue();
    }

    @Test
    void should_get_user_info(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(
            get(urlEqualTo("/userinfo"))
                .willReturn(
                    aResponse().withStatus(200).withBody("{\"sub\": \"248289761001\", \"name\": \"Jane Doe\", \"given_name\": \"Jane\"}")
                )
        );

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getAuthorizationServerUrl()).thenReturn("http://localhost:" + wireMockRuntimeInfo.getHttpPort());
        Mockito.when(configuration.getUserInfoEndpoint()).thenReturn("/userinfo");
        Mockito.when(configuration.getUserInfoEndpointMethod()).thenReturn(HttpMethod.GET.name());

        resource.doStart();

        resource.userInfo(
            "xxxx-xxxx-xxxx-xxxx",
            userInfoResponse -> {
                assertThat(userInfoResponse.isSuccess()).isTrue();
                lock.countDown();
            }
        );

        assertThat(lock.await(10000, TimeUnit.MILLISECONDS)).isTrue();
    }

    @Test
    void should_post_user_info(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(
            post(urlEqualTo("/userinfo"))
                .willReturn(
                    aResponse().withStatus(200).withBody("{\"sub\": \"248289761001\", \"name\": \"Jane Doe\", \"given_name\": \"Jane\"}")
                )
        );

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getAuthorizationServerUrl()).thenReturn("http://localhost:" + wireMockRuntimeInfo.getHttpPort());
        Mockito.when(configuration.getUserInfoEndpoint()).thenReturn("/userinfo");
        Mockito.when(configuration.getUserInfoEndpointMethod()).thenReturn(HttpMethod.POST.name());

        resource.doStart();

        resource.userInfo(
            "xxxx-xxxx-xxxx-xxxx",
            userInfoResponse -> {
                assertThat(userInfoResponse.isSuccess()).isTrue();
                lock.countDown();
            }
        );

        assertThat(lock.await(10000, TimeUnit.MILLISECONDS)).isTrue();
    }

    @Test
    void should_not_get_user_info(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(get(urlEqualTo("/userinfo")).willReturn(aResponse().withStatus(401)));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getAuthorizationServerUrl()).thenReturn("http://localhost:" + wireMockRuntimeInfo.getHttpPort());
        Mockito.when(configuration.getUserInfoEndpoint()).thenReturn("/userinfo");
        Mockito.when(configuration.getUserInfoEndpointMethod()).thenReturn(HttpMethod.GET.name());

        resource.doStart();

        resource.userInfo(
            "xxxx-xxxx-xxxx-xxxx",
            userInfoResponse -> {
                assertThat(userInfoResponse.isSuccess()).isFalse();
                assertThat(userInfoResponse.getPayload()).isEqualTo("An error occurs while getting userinfo from access token");
                lock.countDown();
            }
        );

        assertThat(lock.await(10000, TimeUnit.MILLISECONDS)).isTrue();
    }

    @Test
    void should_get_custom_user_claim(WireMockRuntimeInfo wireMockRuntimeInfo) {
        Mockito.when(configuration.getUserClaim()).thenReturn("customUserClaim");
        assertThat(resource.getUserClaim()).isEqualTo("customUserClaim");
    }

    @Test
    void should_get_default_user_claim() {
        assertThat(resource.getUserClaim()).isEqualTo("sub");
    }
}
