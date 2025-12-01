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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.common.utils.UUID;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.reactive.api.context.DeploymentContext;
import io.gravitee.node.api.Node;
import io.gravitee.node.api.configuration.Configuration;
import io.gravitee.node.api.utils.NodeUtils;
import io.gravitee.node.container.spring.SpringEnvironmentConfiguration;
import io.gravitee.node.vertx.proxy.VertxProxyOptionsUtils;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2ResourceException;
import io.gravitee.resource.oauth2.api.OAuth2ResourceMetadata;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.oauth2.api.openid.UserInfoResponse;
import io.gravitee.resource.oauth2.generic.configuration.OAuth2ResourceConfiguration;
import io.gravitee.resource.oauth2.generic.configuration.OAuth2ResourceConfigurationEvaluator;
import io.vertx.core.Vertx;
import io.vertx.core.http.*;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import javax.inject.Inject;
import lombok.AccessLevel;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class OAuth2GenericResource extends OAuth2Resource<OAuth2ResourceConfiguration> implements ApplicationContextAware {

    public static final String ERROR_CHECKING_OAUTH_2_TOKEN = "An error occurs while checking OAuth2 token";
    public static final String ERROR_GETTING_USERINFO = "An error occurs while getting userinfo from access token";
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

    @Setter(AccessLevel.PACKAGE)
    private OAuth2ResourceConfiguration configuration;

    @Inject
    @Setter
    private DeploymentContext deploymentContext;

    @Override
    public OAuth2ResourceConfiguration configuration() {
        if (configuration == null) {
            return super.configuration();
        }
        return configuration;
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        configuration = new OAuth2ResourceConfigurationEvaluator(configuration()).evalNow(deploymentContext);

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

        if (authorizationServerUrl == null) {
            throw new IllegalArgumentException("Either userInfoEndpointURI or introspectionEndpointURI should be set");
        }

        int authorizationServerPort;
        if (authorizationServerUrl.getPort() != -1) {
            authorizationServerPort = authorizationServerUrl.getPort();
        } else if (HTTPS_SCHEME.equals(authorizationServerUrl.getScheme())) {
            authorizationServerPort = 443;
        } else {
            authorizationServerPort = 80;
        }

        // Safely convert timeout values from long to int, preventing overflow
        int idleTimeout = (int) Math.min(Integer.MAX_VALUE, configuration().getHttpClientOptions().getIdleTimeout());
        int connectTimeout = (int) Math.min(Integer.MAX_VALUE, configuration().getHttpClientOptions().getConnectTimeout());
        int keepAliveTimeout = (int) Math.min(Integer.MAX_VALUE, configuration().getHttpClientOptions().getKeepAliveTimeout());

        httpClientOptions = new HttpClientOptions()
            .setDefaultPort(authorizationServerPort)
            .setDefaultHost(authorizationServerUrl.getHost())
            .setMaxPoolSize(configuration().getHttpClientOptions().getMaxConcurrentConnections())
            .setIdleTimeoutUnit(TimeUnit.MILLISECONDS)
            .setIdleTimeout(idleTimeout)
            .setConnectTimeout(connectTimeout)
            .setKeepAliveTimeout(keepAliveTimeout);

        // Use SSL connection if authorization schema is set to HTTPS
        if (HTTPS_SCHEME.equalsIgnoreCase(authorizationServerUrl.getScheme())) {
            httpClientOptions.setSsl(true).setVerifyHost(false).setTrustAll(true);
        }

        if (configuration().isUseSystemProxy()) {
            try {
                Configuration nodeConfig = new SpringEnvironmentConfiguration(applicationContext.getEnvironment());
                httpClientOptions.setProxyOptions(VertxProxyOptionsUtils.buildProxyOptions(nodeConfig));
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

        StringBuilder uriBuilder = new StringBuilder(introspectionEndpointURI);

        if (configuration.isTokenIsSuppliedByQueryParam()) {
            uriBuilder.append('?').append(configuration.getTokenQueryParamName()).append('=').append(accessToken);
        }

        String endpointURI = uriBuilder.toString();
        logger.debug("Introspect access token by requesting {} [{}]", endpointURI, configuration.getIntrospectionEndpointMethod());

        final HttpMethod httpMethod = HttpMethod.valueOf(configuration.getIntrospectionEndpointMethod().toUpperCase());

        final RequestOptions reqOptions = new RequestOptions()
            .setMethod(httpMethod)
            .setAbsoluteURI(endpointURI)
            .putHeader(HttpHeaderNames.USER_AGENT, userAgent)
            .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()));

        if (configuration().isUseClientAuthorizationHeader()) {
            String authorizationHeader = configuration.getClientAuthorizationHeaderName();
            String authorizationValue =
                configuration.getClientAuthorizationHeaderScheme().trim() +
                AUTHORIZATION_HEADER_SCHEME_SEPARATOR +
                Base64.getEncoder().encodeToString(
                    (configuration.getClientId() + AUTHORIZATION_HEADER_VALUE_BASE64_SEPARATOR + configuration.getClientSecret()).getBytes()
                );
            reqOptions.putHeader(authorizationHeader, authorizationValue);
            logger.debug("Set client authorization using HTTP header {} with value {}", authorizationHeader, authorizationValue);
        }

        // Set `Accept` header to ask for application/json content
        reqOptions.putHeader(HttpHeaderNames.ACCEPT, MediaType.APPLICATION_JSON);

        if (configuration.isTokenIsSuppliedByHttpHeader()) {
            reqOptions.putHeader(configuration.getTokenHeaderName(), accessToken);
        }

        httpClient
            .request(reqOptions)
            .onFailure(event -> {
                logger.error(ERROR_CHECKING_OAUTH_2_TOKEN, event);
                responseHandler.handle(new OAuth2Response(event));
            })
            .onSuccess(request -> {
                request
                    .response(asyncResponse -> {
                        if (asyncResponse.failed()) {
                            logger.error(ERROR_CHECKING_OAUTH_2_TOKEN, asyncResponse.cause());
                            responseHandler.handle(new OAuth2Response(asyncResponse.cause()));
                        } else {
                            final HttpClientResponse response = asyncResponse.result();
                            response.bodyHandler(buffer -> {
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
                                        logger.error("Unable to validate introspection endpoint payload: {}", content, e);
                                        responseHandler.handle(new OAuth2Response(e));
                                    }
                                } else {
                                    logger.error(
                                        "An error occurs while checking OAuth2 token. Request ends with status {}: {}",
                                        response.statusCode(),
                                        buffer
                                    );
                                    responseHandler.handle(new OAuth2Response(new OAuth2ResourceException(ERROR_CHECKING_OAUTH_2_TOKEN)));
                                }
                            });
                        }
                    })
                    .exceptionHandler(event -> {
                        logger.error(ERROR_CHECKING_OAUTH_2_TOKEN, event);
                        responseHandler.handle(new OAuth2Response(event));
                    });

                if (httpMethod == HttpMethod.POST && configuration.isTokenIsSuppliedByFormUrlEncoded()) {
                    request.headers().add(HttpHeaderNames.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
                    request.end(configuration.getTokenFormUrlEncodedName() + '=' + accessToken);
                } else {
                    request.end();
                }
            });
    }

    @Override
    public void userInfo(String accessToken, Handler<UserInfoResponse> responseHandler) {
        HttpClient httpClient = httpClients.computeIfAbsent(Thread.currentThread(), context -> vertx.createHttpClient(httpClientOptions));

        HttpMethod httpMethod = HttpMethod.valueOf(configuration.getUserInfoEndpointMethod().toUpperCase());

        logger.debug("Get userinfo by requesting {} [{}]", userInfoEndpointURI, configuration.getUserInfoEndpointMethod());

        final RequestOptions reqOptions = new RequestOptions()
            .setMethod(httpMethod)
            .setAbsoluteURI(userInfoEndpointURI)
            .putHeader(HttpHeaderNames.USER_AGENT, userAgent)
            .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()))
            .putHeader(HttpHeaderNames.AUTHORIZATION, AUTHORIZATION_HEADER_BEARER_SCHEME + accessToken);

        httpClient
            .request(reqOptions)
            .onFailure(event -> {
                logger.error(ERROR_GETTING_USERINFO, event);
                responseHandler.handle(new UserInfoResponse(event));
            })
            .onSuccess(request ->
                request
                    .response(asyncResponse -> {
                        if (asyncResponse.failed()) {
                            logger.error(ERROR_GETTING_USERINFO, asyncResponse.cause());
                            responseHandler.handle(new UserInfoResponse(asyncResponse.cause()));
                        } else {
                            final HttpClientResponse response = asyncResponse.result();
                            response.bodyHandler(buffer -> {
                                logger.debug("Userinfo endpoint returns a response with a {} status code", response.statusCode());

                                if (response.statusCode() == HttpStatusCode.OK_200) {
                                    responseHandler.handle(new UserInfoResponse(true, buffer.toString()));
                                } else {
                                    logger.error(
                                        "An error occurs while getting userinfo from access token. Request ends with status {}: {}",
                                        response.statusCode(),
                                        buffer
                                    );
                                    responseHandler.handle(new UserInfoResponse(new OAuth2ResourceException(ERROR_GETTING_USERINFO)));
                                }
                            });
                        }
                    })
                    .exceptionHandler(event -> {
                        logger.error(ERROR_GETTING_USERINFO, event);
                        responseHandler.handle(new UserInfoResponse(event));
                    })
                    .end()
            );
    }

    @Override
    public String getUserClaim() {
        if (configuration().getUserClaim() != null && !configuration().getUserClaim().isEmpty()) {
            return configuration().getUserClaim();
        }
        return super.getUserClaim();
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }

    @Override
    public OAuth2ResourceMetadata getProtectedResourceMetadata(String protectedResourceUri) {
        String authServerMetadataEndpoint = configuration.getAuthorizationServerMetadataEndpoint();
        String authServerEndpoint = authServerMetadataEndpoint.substring(0, authServerMetadataEndpoint.lastIndexOf("/.well-known/"));
        URI authServerUri = URI.create(configuration.getAuthorizationServerUrl() + authServerEndpoint);
        String authorizationServer = authServerUri.normalize().toString();
        return new OAuth2ResourceMetadata(protectedResourceUri, List.of(authorizationServer), null);
    }
}
