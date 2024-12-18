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
import io.gravitee.common.http.HttpMethod;
import io.gravitee.common.http.MediaType;
import io.gravitee.el.TemplateEngine;
import io.gravitee.el.spel.context.SecuredResolver;
import io.gravitee.node.api.Node;
import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.oauth2.generic.configuration.OAuth2ResourceConfiguration;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.vertx.core.Vertx;
import java.lang.reflect.Field;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
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

        resource.introspect(
            "xxxx-xxxx-xxxx-xxxx",
            oAuth2Response -> {
                assertThat(oAuth2Response.isSuccess()).isTrue();
                check.set(true);
            }
        );

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_not_validate_access_token(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(401)));

        AtomicBoolean check = new AtomicBoolean();

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect(
            "xxxx-xxxx-xxxx-xxxx",
            oAuth2Response -> {
                assertThat(oAuth2Response.isSuccess()).isFalse();
                assertThat(oAuth2Response.getPayload()).isEqualTo("An error occurs while checking OAuth2 token");
                check.set(true);
            }
        );

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_not_validate_access_token_not_active(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"active\": \"false\"}")));

        AtomicBoolean check = new AtomicBoolean();

        configuration.setIntrospectionEndpoint("http://localhost:" + wireMockRuntimeInfo.getHttpPort() + "/oauth/introspect");
        configuration.setIntrospectionEndpointMethod(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect(
            "xxxx-xxxx-xxxx-xxxx",
            oAuth2Response -> {
                assertThat(oAuth2Response.isSuccess()).isFalse();
                check.set(true);
            }
        );

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_get_user_info(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(
            get(urlEqualTo("/userinfo"))
                .willReturn(
                    aResponse().withStatus(200).withBody("{\"sub\": \"248289761001\", \"name\": \"Jane Doe\", \"given_name\": \"Jane\"}")
                )
        );

        AtomicBoolean check = new AtomicBoolean();

        configuration.setAuthorizationServerUrl("http://localhost:" + wireMockRuntimeInfo.getHttpPort());
        configuration.setUserInfoEndpoint("/userinfo");
        configuration.setUserInfoEndpointMethod(HttpMethod.GET.name());

        resource.doStart();

        resource.userInfo(
            "xxxx-xxxx-xxxx-xxxx",
            userInfoResponse -> {
                assertThat(userInfoResponse.isSuccess()).isTrue();
                check.set(true);
            }
        );

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_post_user_info(WireMockRuntimeInfo wireMockRuntimeInfo) throws Exception {
        stubFor(
            post(urlEqualTo("/userinfo"))
                .willReturn(
                    aResponse().withStatus(200).withBody("{\"sub\": \"248289761001\", \"name\": \"Jane Doe\", \"given_name\": \"Jane\"}")
                )
        );

        AtomicBoolean check = new AtomicBoolean();

        configuration.setAuthorizationServerUrl("http://localhost:" + wireMockRuntimeInfo.getHttpPort());
        configuration.setUserInfoEndpoint("/userinfo");
        configuration.setUserInfoEndpointMethod(HttpMethod.POST.name());

        resource.doStart();

        resource.userInfo(
            "xxxx-xxxx-xxxx-xxxx",
            userInfoResponse -> {
                assertThat(userInfoResponse.isSuccess()).isTrue();
                check.set(true);
            }
        );

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

        resource.userInfo(
            "xxxx-xxxx-xxxx-xxxx",
            userInfoResponse -> {
                assertThat(userInfoResponse.isSuccess()).isFalse();
                assertThat(userInfoResponse.getPayload()).isEqualTo("An error occurs while getting userinfo from access token");
                check.set(true);
            }
        );

        Awaitility.await().atMost(10, TimeUnit.SECONDS).untilTrue(check);
    }

    @Test
    void should_get_default_user_claim() {
        assertThat(resource.getUserClaim()).isEqualTo("sub");
    }
}
