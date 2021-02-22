/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.oauth2.generic;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.common.http.MediaType;
import io.gravitee.node.api.Node;
import io.gravitee.resource.oauth2.generic.configuration.OAuth2ResourceConfiguration;
import io.vertx.core.Vertx;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.context.ApplicationContext;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2GenericResourceTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort());

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private OAuth2ResourceConfiguration configuration;

    @Mock
    private Node node;

    @InjectMocks
    private OAuth2GenericResource resource;

    @Before
    public void init() {
        Mockito.when(applicationContext.getBean(Node.class)).thenReturn(node);
        Mockito.when(applicationContext.getBean(Vertx.class)).thenReturn(Vertx.vertx());
    }

    @Test
    public void shouldCallWithHeader() throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getIntrospectionEndpoint()).thenReturn("http://localhost:" + wireMockRule.port() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());
        Mockito.when(configuration.isTokenIsSuppliedByHttpHeader()).thenReturn(true);
        Mockito.when(configuration.getTokenHeaderName()).thenReturn(HttpHeaders.AUTHORIZATION);

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> lock.countDown());

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));

        verify(postRequestedFor(urlPathEqualTo("/oauth/introspect")).withHeader(HttpHeaders.AUTHORIZATION, equalTo(accessToken)));
    }

    @Test
    public void shouldCallWithAuthorizationServerURL() throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getAuthorizationServerUrl()).thenReturn("http://localhost:" + wireMockRule.port());
        Mockito.when(configuration.getIntrospectionEndpoint()).thenReturn("/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());
        Mockito.when(configuration.isTokenIsSuppliedByHttpHeader()).thenReturn(true);
        Mockito.when(configuration.getTokenHeaderName()).thenReturn(HttpHeaders.AUTHORIZATION);

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> lock.countDown());

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));

        verify(postRequestedFor(urlPathEqualTo("/oauth/introspect")).withHeader(HttpHeaders.AUTHORIZATION, equalTo(accessToken)));
    }

    @Test
    public void shouldCallWithQueryParam() throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(
            post(urlPathEqualTo("/oauth/introspect"))
                .withQueryParam("token", equalTo(accessToken))
                .willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}"))
        );

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getIntrospectionEndpoint()).thenReturn("http://localhost:" + wireMockRule.port() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());
        Mockito.when(configuration.isTokenIsSuppliedByQueryParam()).thenReturn(true);
        Mockito.when(configuration.getTokenQueryParamName()).thenReturn("token");

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> lock.countDown());

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));

        verify(postRequestedFor(urlPathEqualTo(("/oauth/introspect"))).withQueryParam("token", equalTo(accessToken)));
    }

    @Test
    public void shouldCallWithFormBody() throws Exception {
        String accessToken = "xxxx-xxxx-xxxx-xxxx";
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getIntrospectionEndpoint()).thenReturn("http://localhost:" + wireMockRule.port() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());
        Mockito.when(configuration.isTokenIsSuppliedByFormUrlEncoded()).thenReturn(true);
        Mockito.when(configuration.getTokenFormUrlEncodedName()).thenReturn("token");

        resource.doStart();

        resource.introspect(accessToken, oAuth2Response -> lock.countDown());

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));

        verify(
            postRequestedFor(urlEqualTo("/oauth/introspect"))
                .withHeader(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_FORM_URLENCODED))
                .withRequestBody(equalTo("token=" + accessToken))
        );
    }

    @Test
    public void shouldValidateAccessToken() throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"key\": \"value\"}")));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getIntrospectionEndpoint()).thenReturn("http://localhost:" + wireMockRule.port() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect(
            "xxxx-xxxx-xxxx-xxxx",
            oAuth2Response -> {
                Assert.assertTrue(oAuth2Response.isSuccess());
                lock.countDown();
            }
        );

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));
    }

    @Test
    public void shouldNotValidateAccessToken() throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(401)));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getIntrospectionEndpoint()).thenReturn("http://localhost:" + wireMockRule.port() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect(
            "xxxx-xxxx-xxxx-xxxx",
            oAuth2Response -> {
                Assert.assertFalse(oAuth2Response.isSuccess());
                lock.countDown();
            }
        );

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));
    }

    @Test
    public void shouldNotValidateAccessToken_notActive() throws Exception {
        stubFor(post(urlEqualTo("/oauth/introspect")).willReturn(aResponse().withStatus(200).withBody("{\"active\": \"false\"}")));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getIntrospectionEndpoint()).thenReturn("http://localhost:" + wireMockRule.port() + "/oauth/introspect");
        Mockito.when(configuration.getIntrospectionEndpointMethod()).thenReturn(HttpMethod.POST.name());

        resource.doStart();

        resource.introspect(
            "xxxx-xxxx-xxxx-xxxx",
            oAuth2Response -> {
                Assert.assertFalse(oAuth2Response.isSuccess());
                lock.countDown();
            }
        );

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));
    }

    @Test
    public void shouldGetUserInfo() throws Exception {
        stubFor(
            get(urlEqualTo("/userinfo"))
                .willReturn(
                    aResponse().withStatus(200).withBody("{\"sub\": \"248289761001\", \"name\": \"Jane Doe\", \"given_name\": \"Jane\"}")
                )
        );

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getAuthorizationServerUrl()).thenReturn("http://localhost:" + wireMockRule.port());
        Mockito.when(configuration.getUserInfoEndpoint()).thenReturn("/userinfo");
        Mockito.when(configuration.getUserInfoEndpointMethod()).thenReturn(HttpMethod.GET.name());

        resource.doStart();

        resource.userInfo(
            "xxxx-xxxx-xxxx-xxxx",
            userInfoResponse -> {
                Assert.assertTrue(userInfoResponse.isSuccess());
                lock.countDown();
            }
        );

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));
    }

    @Test
    public void shouldPostUserInfo() throws Exception {
        stubFor(
            post(urlEqualTo("/userinfo"))
                .willReturn(
                    aResponse().withStatus(200).withBody("{\"sub\": \"248289761001\", \"name\": \"Jane Doe\", \"given_name\": \"Jane\"}")
                )
        );

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getAuthorizationServerUrl()).thenReturn("http://localhost:" + wireMockRule.port());
        Mockito.when(configuration.getUserInfoEndpoint()).thenReturn("/userinfo");
        Mockito.when(configuration.getUserInfoEndpointMethod()).thenReturn(HttpMethod.POST.name());

        resource.doStart();

        resource.userInfo(
            "xxxx-xxxx-xxxx-xxxx",
            userInfoResponse -> {
                Assert.assertTrue(userInfoResponse.isSuccess());
                lock.countDown();
            }
        );

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));
    }

    @Test
    public void shouldNotGetUserInfo() throws Exception {
        stubFor(get(urlEqualTo("/userinfo")).willReturn(aResponse().withStatus(401)));

        final CountDownLatch lock = new CountDownLatch(1);

        Mockito.when(configuration.getAuthorizationServerUrl()).thenReturn("http://localhost:" + wireMockRule.port());
        Mockito.when(configuration.getUserInfoEndpoint()).thenReturn("/userinfo");
        Mockito.when(configuration.getUserInfoEndpointMethod()).thenReturn(HttpMethod.GET.name());

        resource.doStart();

        resource.userInfo(
            "xxxx-xxxx-xxxx-xxxx",
            userInfoResponse -> {
                Assert.assertFalse(userInfoResponse.isSuccess());
                lock.countDown();
            }
        );

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));
    }
}
