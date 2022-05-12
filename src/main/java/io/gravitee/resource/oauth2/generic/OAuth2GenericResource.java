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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.common.util.VertxProxyOptionsUtils;
import io.gravitee.common.utils.UUID;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.node.api.Node;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.node.api.utils.NodeUtils;
import io.gravitee.node.container.spring.SpringEnvironmentConfiguration;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.oauth2.api.openid.UserInfoResponse;
import io.gravitee.resource.oauth2.generic.configuration.OAuth2ResourceConfiguration;
import io.vertx.core.AsyncResult;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import io.vertx.core.http.*;
import io.vertx.core.net.ProxyOptions;
import io.vertx.core.net.ProxyType;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.env.Environment;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class OAuth2GenericResource extends OAuth2Resource<OAuth2ResourceConfiguration> implements ApplicationContextAware {

    private final Logger logger = LoggerFactory.getLogger(OAuth2GenericResource.class);

    // Pattern reuse for duplicate slash removal
    private static final Pattern DUPLICATE_SLASH_REMOVER = Pattern.compile("(?<!(http:|https:))[//]+");

    private static final String HTTPS_SCHEME = "https";

    private static final String AUTHORIZATION_HEADER_BEARER_SCHEME = "Bearer ";
    private static final char AUTHORIZATION_HEADER_SCHEME_SEPARATOR = ' ';
    private static final char AUTHORIZATION_HEADER_VALUE_BASE64_SEPARATOR = ':';

    private ApplicationContext applicationContext;

    private final Map<Thread, HttpClient> httpClients = new ConcurrentHashMap<>();

    private HttpClientOptions httpClientOptions;

    private Vertx vertx;

    private String userAgent;

    private String introspectionEndpointURI;

    private String userInfoEndpointURI;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        logger.info("Starting an OAuth2 resource using authorization server at {}", configuration().getAuthorizationServerUrl());

        String sAuthorizationServerUrl = configuration().getAuthorizationServerUrl();

        if (sAuthorizationServerUrl != null && !sAuthorizationServerUrl.isEmpty()) {
            introspectionEndpointURI = configuration().getAuthorizationServerUrl() + '/' + configuration().getIntrospectionEndpoint();
            userInfoEndpointURI = configuration().getAuthorizationServerUrl() + '/' + configuration().getUserInfoEndpoint();
        } else {
            introspectionEndpointURI = configuration().getIntrospectionEndpoint();
            userInfoEndpointURI = configuration().getUserInfoEndpoint();
        }

        URI authorizationServerUrl = null;

        if (userInfoEndpointURI != null) {
            userInfoEndpointURI = DUPLICATE_SLASH_REMOVER.matcher(userInfoEndpointURI).replaceAll("/");
            authorizationServerUrl = URI.create(userInfoEndpointURI);
        }

        if (introspectionEndpointURI != null) {
            introspectionEndpointURI = DUPLICATE_SLASH_REMOVER.matcher(introspectionEndpointURI).replaceAll("/");
            authorizationServerUrl = URI.create(introspectionEndpointURI);
        }

        int authorizationServerPort = authorizationServerUrl.getPort() != -1
            ? authorizationServerUrl.getPort()
            : (HTTPS_SCHEME.equals(authorizationServerUrl.getScheme()) ? 443 : 80);
        String authorizationServerHost = authorizationServerUrl.getHost();

        httpClientOptions =
            new HttpClientOptions()
                .setDefaultPort(authorizationServerPort)
                .setDefaultHost(authorizationServerHost)
                .setIdleTimeout(60)
                .setConnectTimeout(10000);

        // Use SSL connection if authorization schema is set to HTTPS
        if (HTTPS_SCHEME.equalsIgnoreCase(authorizationServerUrl.getScheme())) {
            httpClientOptions.setSsl(true).setVerifyHost(false).setTrustAll(true);
        }

        if (configuration().isUseSystemProxy()) {
            try {
                Configuration nodeConfig = new SpringEnvironmentConfiguration(applicationContext.getEnvironment());
                VertxProxyOptionsUtils.setSystemProxy(httpClientOptions, nodeConfig);
            } catch (IllegalStateException e) {
                logger.warn(
                    "OAuth2 resource requires a system proxy to be defined but some configurations are missing or not well defined: {}",
                    e.getMessage()
                );
                logger.warn("Ignoring system proxy");
            }
        }

        userAgent = NodeUtils.userAgent(applicationContext.getBean(Node.class));
        vertx = applicationContext.getBean(Vertx.class);
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        httpClients
            .values()
            .forEach(httpClient -> {
                try {
                    httpClient.close();
                } catch (IllegalStateException ise) {
                    logger.warn(ise.getMessage());
                }
            });
    }

    @Override
    public void introspect(String accessToken, Handler<OAuth2Response> responseHandler) {
        HttpClient httpClient = httpClients.computeIfAbsent(Thread.currentThread(), context -> vertx.createHttpClient(httpClientOptions));

        OAuth2ResourceConfiguration configuration = configuration();
        StringBuilder introspectionUriBuilder = new StringBuilder(introspectionEndpointURI);

        if (configuration.isTokenIsSuppliedByQueryParam()) {
            introspectionUriBuilder.append('?').append(configuration.getTokenQueryParamName()).append('=').append(accessToken);
        }

        String introspectionEndpointURI = introspectionUriBuilder.toString();
        logger.debug(
            "Introspect access token by requesting {} [{}]",
            introspectionEndpointURI,
            configuration.getIntrospectionEndpointMethod()
        );

        final HttpMethod httpMethod = HttpMethod.valueOf(configuration.getIntrospectionEndpointMethod().toUpperCase());

        final RequestOptions reqOptions = new RequestOptions()
            .setMethod(httpMethod)
            .setAbsoluteURI(introspectionEndpointURI)
            .setTimeout(30000L)
            .putHeader(HttpHeaders.USER_AGENT, userAgent)
            .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()));

        if (configuration().isUseClientAuthorizationHeader()) {
            String authorizationHeader = configuration.getClientAuthorizationHeaderName();
            String authorizationValue =
                configuration.getClientAuthorizationHeaderScheme().trim() +
                AUTHORIZATION_HEADER_SCHEME_SEPARATOR +
                Base64
                    .getEncoder()
                    .encodeToString(
                        (
                            configuration.getClientId() + AUTHORIZATION_HEADER_VALUE_BASE64_SEPARATOR + configuration.getClientSecret()
                        ).getBytes()
                    );
            reqOptions.putHeader(authorizationHeader, authorizationValue);
            logger.debug("Set client authorization using HTTP header {} with value {}", authorizationHeader, authorizationValue);
        }

        // Set `Accept` header to ask for application/json content
        reqOptions.putHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);

        if (configuration.isTokenIsSuppliedByHttpHeader()) {
            reqOptions.putHeader(configuration.getTokenHeaderName(), accessToken);
        }

        httpClient
            .request(reqOptions)
            .onFailure(
                new io.vertx.core.Handler<Throwable>() {
                    @Override
                    public void handle(Throwable event) {
                        logger.error("An error occurs while checking OAuth2 token", event);
                        responseHandler.handle(new OAuth2Response(false, event.getMessage()));
                    }
                }
            )
            .onSuccess(
                new io.vertx.core.Handler<HttpClientRequest>() {
                    @Override
                    public void handle(HttpClientRequest request) {
                        request
                            .response(
                                new io.vertx.core.Handler<AsyncResult<HttpClientResponse>>() {
                                    @Override
                                    public void handle(AsyncResult<HttpClientResponse> asyncResponse) {
                                        if (asyncResponse.failed()) {
                                            logger.error("An error occurs while checking OAuth2 token", asyncResponse.cause());
                                            responseHandler.handle(new OAuth2Response(false, asyncResponse.cause().getMessage()));
                                        } else {
                                            final HttpClientResponse response = asyncResponse.result();
                                            response.bodyHandler(buffer -> {
                                                logger.debug(
                                                    "Userinfo endpoint returns a response with a {} status code",
                                                    response.statusCode()
                                                );

                                                logger.debug(
                                                    "Introspection endpoint returns a response with a {} status code",
                                                    response.statusCode()
                                                );
                                                if (response.statusCode() == HttpStatusCode.OK_200) {
                                                    // According to RFC 7662 : Note that a properly formed and authorized query for an inactive or
                                                    // otherwise invalid token (or a token the protected resource is not
                                                    // allowed to know about) is not considered an error response by this
                                                    // specification.  In these cases, the authorization server MUST instead
                                                    // respond with an introspection response with the "active" field set to
                                                    // "false" as described in Section 2.2.
                                                    String content = buffer.toString();

                                                    try {
                                                        JsonNode introspectNode = MAPPER.readTree(content);
                                                        JsonNode activeNode = introspectNode.get("active");
                                                        if (activeNode != null) {
                                                            boolean isActive = activeNode.asBoolean();
                                                            responseHandler.handle(new OAuth2Response(isActive, content));
                                                        } else {
                                                            responseHandler.handle(new OAuth2Response(true, content));
                                                        }
                                                    } catch (IOException e) {
                                                        logger.error("Unable to validate introspection endpoint payload: {}", content);
                                                        responseHandler.handle(new OAuth2Response(false, content));
                                                    }
                                                } else {
                                                    responseHandler.handle(new OAuth2Response(false, buffer.toString()));
                                                }
                                            });
                                        }
                                    }
                                }
                            )
                            .exceptionHandler(
                                new io.vertx.core.Handler<Throwable>() {
                                    @Override
                                    public void handle(Throwable event) {
                                        logger.error("An error occurs while checking OAuth2 token", event);
                                        responseHandler.handle(new OAuth2Response(false, event.getMessage()));
                                    }
                                }
                            );

                        if (httpMethod == HttpMethod.POST && configuration.isTokenIsSuppliedByFormUrlEncoded()) {
                            request.headers().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
                            request.end(configuration.getTokenFormUrlEncodedName() + '=' + accessToken);
                        } else {
                            request.end();
                        }
                    }
                }
            );
    }

    @Override
    public void userInfo(String accessToken, Handler<UserInfoResponse> responseHandler) {
        HttpClient httpClient = httpClients.computeIfAbsent(Thread.currentThread(), context -> vertx.createHttpClient(httpClientOptions));

        OAuth2ResourceConfiguration configuration = configuration();

        HttpMethod httpMethod = HttpMethod.valueOf(configuration.getUserInfoEndpointMethod().toUpperCase());

        logger.debug("Get userinfo by requesting {} [{}]", userInfoEndpointURI, configuration.getUserInfoEndpointMethod());

        final RequestOptions reqOptions = new RequestOptions()
            .setMethod(httpMethod)
            .setAbsoluteURI(userInfoEndpointURI)
            .setTimeout(30000L)
            .putHeader(HttpHeaders.USER_AGENT, userAgent)
            .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()))
            .putHeader(HttpHeaders.AUTHORIZATION, AUTHORIZATION_HEADER_BEARER_SCHEME + accessToken);

        httpClient
            .request(reqOptions)
            .onFailure(
                new io.vertx.core.Handler<Throwable>() {
                    @Override
                    public void handle(Throwable event) {
                        logger.error("An error occurs while getting userinfo from access token", event);
                        responseHandler.handle(new UserInfoResponse(false, event.getMessage()));
                    }
                }
            )
            .onSuccess(
                new io.vertx.core.Handler<HttpClientRequest>() {
                    @Override
                    public void handle(HttpClientRequest request) {
                        request
                            .response(
                                new io.vertx.core.Handler<AsyncResult<HttpClientResponse>>() {
                                    @Override
                                    public void handle(AsyncResult<HttpClientResponse> asyncResponse) {
                                        if (asyncResponse.failed()) {
                                            logger.error("An error occurs while introspecting access token", asyncResponse.cause());
                                            responseHandler.handle(new UserInfoResponse(false, asyncResponse.cause().getMessage()));
                                        } else {
                                            final HttpClientResponse response = asyncResponse.result();
                                            response.bodyHandler(buffer -> {
                                                logger.debug(
                                                    "Userinfo endpoint returns a response with a {} status code",
                                                    response.statusCode()
                                                );

                                                if (response.statusCode() == HttpStatusCode.OK_200) {
                                                    responseHandler.handle(new UserInfoResponse(true, buffer.toString()));
                                                } else {
                                                    responseHandler.handle(new UserInfoResponse(false, buffer.toString()));
                                                }
                                            });
                                        }
                                    }
                                }
                            )
                            .exceptionHandler(
                                new io.vertx.core.Handler<Throwable>() {
                                    @Override
                                    public void handle(Throwable event) {
                                        logger.error("An error occurs while getting userinfo from access token", event);
                                        responseHandler.handle(new UserInfoResponse(false, event.getMessage()));
                                    }
                                }
                            )
                            .end();
                    }
                }
            );
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}
