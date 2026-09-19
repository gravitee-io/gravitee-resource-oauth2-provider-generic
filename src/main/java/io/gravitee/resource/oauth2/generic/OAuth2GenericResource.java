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
import io.gravitee.node.vertx.client.http.VertxHttpClientFactory;
import io.gravitee.node.vertx.proxy.VertxProxyOptionsUtils;
import io.gravitee.plugin.configurations.ssl.SslOptions;
import io.gravitee.plugin.mappers.HttpClientOptionsMapper;
import io.gravitee.plugin.mappers.HttpProxyOptionsMapper;
import io.gravitee.plugin.mappers.SslOptionsMapper;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2ResourceException;
import io.gravitee.resource.oauth2.api.OAuth2ResourceMetadata;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.oauth2.api.openid.UserInfoResponse;
import io.gravitee.resource.oauth2.api.tokenexchange.TokenExchangeRequest;
import io.gravitee.resource.oauth2.api.tokenexchange.TokenExchangeResponse;
import io.gravitee.resource.oauth2.generic.configuration.OAuth2ResourceConfiguration;
import io.gravitee.resource.oauth2.generic.configuration.OAuth2ResourceConfigurationEvaluator;
import io.vertx.core.Vertx;
import io.vertx.core.http.*;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.inject.Inject;
import lombok.AccessLevel;
import lombok.CustomLog;
import lombok.Setter;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@CustomLog
public class OAuth2GenericResource extends OAuth2Resource<OAuth2ResourceConfiguration> implements ApplicationContextAware {

    public static final String ERROR_CHECKING_OAUTH_2_TOKEN = "An error occurs while checking OAuth2 token";
    public static final String ERROR_GETTING_USERINFO = "An error occurs while getting userinfo from access token";
    public static final String ERROR_EXCHANGING_TOKEN = "An error occurs while exchanging token";

    private static final String TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String[] REQUIRED_TOKEN_EXCHANGE_FIELDS = { "access_token", "issued_token_type", "token_type" };

    // Pattern reuse for duplicate slash removal
    private static final Pattern DUPLICATE_SLASH_REMOVER = Pattern.compile("(?<!(http:|https:))[//]+");

    private static final String HTTPS_SCHEME = "https";

    private static final String AUTHORIZATION_HEADER_BEARER_SCHEME = "Bearer ";
    private static final char AUTHORIZATION_HEADER_SCHEME_SEPARATOR = ' ';
    private static final char AUTHORIZATION_HEADER_VALUE_BASE64_SEPARATOR = ':';

    private ApplicationContext applicationContext;

    private HttpClient httpClient;

    private String userAgent;

    private String introspectionEndpointURI;

    private String userInfoEndpointURI;

    private String tokenExchangeEndpointURL;

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

        log.info("Starting an OAuth2 resource using authorization server at {}", configuration().getAuthorizationServerUrl());

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

        var target = new URL(
            authorizationServerUrl.getScheme(),
            authorizationServerUrl.getHost(),
            authorizationServerPort,
            authorizationServerUrl.toURL().getFile()
        );

        tokenExchangeEndpointURL = resolveTokenExchangeEndpoint(
            configuration().getTokenExchangeEndpoint(),
            sAuthorizationServerUrl,
            target
        );

        httpClient = VertxHttpClientFactory.builder()
            .vertx(applicationContext.getBean(io.vertx.rxjava3.core.Vertx.class))
            .nodeConfiguration(new SpringEnvironmentConfiguration(applicationContext.getEnvironment()))
            .defaultTarget(target.toString())
            .httpOptions(HttpClientOptionsMapper.INSTANCE.map(configuration().getHttpClientOptions()))
            .sslOptions(SslOptionsMapper.INSTANCE.map(configuration().getSslOptions()))
            .proxyOptions(HttpProxyOptionsMapper.INSTANCE.map(configuration().getHttpProxyOptions()))
            .build()
            .createHttpClient()
            .getDelegate();

        userAgent = NodeUtils.userAgent(applicationContext.getBean(Node.class));
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        try {
            httpClient.close();
        } catch (IllegalStateException ise) {
            log.warn(ise.getMessage());
        }
    }

    @Override
    public void introspect(String accessToken, Handler<OAuth2Response> responseHandler) {
        StringBuilder uriBuilder = new StringBuilder(introspectionEndpointURI);

        if (configuration.isTokenIsSuppliedByQueryParam()) {
            uriBuilder.append('?').append(configuration.getTokenQueryParamName()).append('=').append(accessToken);
        }

        String endpointURI = uriBuilder.toString();
        log.debug("Introspect access token by requesting {} [{}]", endpointURI, configuration.getIntrospectionEndpointMethod());

        final HttpMethod httpMethod = HttpMethod.valueOf(configuration.getIntrospectionEndpointMethod().toUpperCase());

        final RequestOptions reqOptions = new RequestOptions()
            .setMethod(httpMethod)
            .setAbsoluteURI(endpointURI)
            .putHeader(HttpHeaderNames.USER_AGENT, userAgent)
            .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()));

        if (configuration().isUseClientAuthorizationHeader()) {
            String authorizationHeader = configuration().getClientAuthorizationHeaderName();
            reqOptions.putHeader(authorizationHeader, clientAuthorizationHeaderValue());
            log.debug("Set client authorization using HTTP header {}", authorizationHeader);
        }

        // Set `Accept` header to ask for application/json content
        reqOptions.putHeader(HttpHeaderNames.ACCEPT, MediaType.APPLICATION_JSON);

        if (configuration.isTokenIsSuppliedByHttpHeader()) {
            reqOptions.putHeader(configuration.getTokenHeaderName(), accessToken);
        }

        httpClient
            .request(reqOptions)
            .onFailure(event -> {
                log.error(ERROR_CHECKING_OAUTH_2_TOKEN, event);
                responseHandler.handle(new OAuth2Response(event));
            })
            .onSuccess(request -> {
                request
                    .response()
                    .onComplete(asyncResponse -> {
                        if (asyncResponse.failed()) {
                            log.error(ERROR_CHECKING_OAUTH_2_TOKEN, asyncResponse.cause());
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
                                        log.error("Unable to validate introspection endpoint payload: {}", content, e);
                                        responseHandler.handle(new OAuth2Response(e));
                                    }
                                } else {
                                    log.error(
                                        "An error occurs while checking OAuth2 token. Request ends with status {}: {}",
                                        response.statusCode(),
                                        buffer
                                    );
                                    responseHandler.handle(new OAuth2Response(new OAuth2ResourceException(ERROR_CHECKING_OAUTH_2_TOKEN)));
                                }
                            });
                        }
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
        HttpMethod httpMethod = HttpMethod.valueOf(configuration.getUserInfoEndpointMethod().toUpperCase());

        log.debug("Get userinfo by requesting {} [{}]", userInfoEndpointURI, configuration.getUserInfoEndpointMethod());

        final RequestOptions reqOptions = new RequestOptions()
            .setMethod(httpMethod)
            .setAbsoluteURI(userInfoEndpointURI)
            .putHeader(HttpHeaderNames.USER_AGENT, userAgent)
            .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()))
            .putHeader(HttpHeaderNames.AUTHORIZATION, AUTHORIZATION_HEADER_BEARER_SCHEME + accessToken);

        httpClient
            .request(reqOptions)
            .onFailure(event -> {
                log.error(ERROR_GETTING_USERINFO, event);
                responseHandler.handle(new UserInfoResponse(event));
            })
            .onSuccess(request -> {
                request
                    .response()
                    .onComplete(asyncResponse -> {
                        if (asyncResponse.failed()) {
                            log.error(ERROR_GETTING_USERINFO, asyncResponse.cause());
                            responseHandler.handle(new UserInfoResponse(asyncResponse.cause()));
                        } else {
                            final HttpClientResponse response = asyncResponse.result();
                            response.bodyHandler(buffer -> {
                                log.debug("Userinfo endpoint returns a response with a {} status code", response.statusCode());

                                if (response.statusCode() == HttpStatusCode.OK_200) {
                                    responseHandler.handle(new UserInfoResponse(true, buffer.toString()));
                                } else {
                                    log.error(
                                        "An error occurs while getting userinfo from access token. Request ends with status {}: {}",
                                        response.statusCode(),
                                        buffer
                                    );
                                    responseHandler.handle(new UserInfoResponse(new OAuth2ResourceException(ERROR_GETTING_USERINFO)));
                                }
                            });
                        }
                    });
                request.end();
            });
    }

    @Override
    public void tokenExchange(TokenExchangeRequest tokenExchangeRequest, Handler<TokenExchangeResponse> responseHandler) {
        String validationError = validateTokenExchangeRequest(tokenExchangeRequest);
        if (validationError != null) {
            responseHandler.handle(new TokenExchangeResponse(new IllegalArgumentException(validationError)));
            return;
        }

        log.debug("Exchange token by requesting {}", tokenExchangeEndpointURL);

        final RequestOptions reqOptions;
        final String body;
        try {
            reqOptions = new RequestOptions()
                .setMethod(HttpMethod.POST)
                .setAbsoluteURI(tokenExchangeEndpointURL)
                .putHeader(HttpHeaderNames.USER_AGENT, userAgent)
                .putHeader("X-Gravitee-Request-Id", UUID.toString(UUID.random()))
                .putHeader(HttpHeaderNames.ACCEPT, MediaType.APPLICATION_JSON)
                .putHeader(HttpHeaderNames.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

            final Map<String, String> form = buildTokenExchangeForm(tokenExchangeRequest);
            applyClientAuthentication(reqOptions, form);
            body = encodeForm(form);
        } catch (RuntimeException e) {
            // The endpoint is validated at start, so this is defensive: every failure must reach the handler.
            responseHandler.handle(new TokenExchangeResponse(e));
            return;
        }

        httpClient
            .request(reqOptions)
            .onFailure(event -> {
                log.error(ERROR_EXCHANGING_TOKEN, event);
                responseHandler.handle(new TokenExchangeResponse(event));
            })
            .onSuccess(request -> {
                request
                    .response()
                    .onComplete(asyncResponse -> {
                        if (asyncResponse.failed()) {
                            log.error(ERROR_EXCHANGING_TOKEN, asyncResponse.cause());
                            responseHandler.handle(new TokenExchangeResponse(asyncResponse.cause()));
                        } else {
                            final HttpClientResponse response = asyncResponse.result();
                            response.bodyHandler(buffer -> {
                                log.debug("Token exchange endpoint returns a response with a {} status code", response.statusCode());

                                if (response.statusCode() == HttpStatusCode.OK_200) {
                                    handleTokenExchangeSuccess(buffer.toString(), responseHandler);
                                } else {
                                    handleTokenExchangeError(response.statusCode(), buffer.toString(), responseHandler);
                                }
                            });
                        }
                    });
                request.end(body);
            });
    }

    /**
     * @return a message describing why the request cannot be performed, or {@code null} when it is valid.
     */
    private String validateTokenExchangeRequest(TokenExchangeRequest tokenExchangeRequest) {
        if (tokenExchangeEndpointURL == null) {
            return "tokenExchangeEndpoint is not configured";
        }
        if (tokenExchangeRequest == null) {
            return "tokenExchangeRequest cannot be null";
        }
        if (isBlank(tokenExchangeRequest.getSubjectToken())) {
            return "subject_token is required";
        }
        if (isBlank(tokenExchangeRequest.getSubjectTokenType())) {
            return "subject_token_type is required";
        }
        return null;
    }

    private Map<String, String> buildTokenExchangeForm(TokenExchangeRequest tokenExchangeRequest) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", TOKEN_EXCHANGE_GRANT_TYPE);
        form.put("subject_token", tokenExchangeRequest.getSubjectToken());
        form.put("subject_token_type", tokenExchangeRequest.getSubjectTokenType());
        putIfPresent(form, "resource", tokenExchangeRequest.getResource());
        putIfPresent(form, "audience", tokenExchangeRequest.getAudience());
        putIfPresent(form, "scope", tokenExchangeRequest.getScope());
        putIfPresent(form, "requested_token_type", tokenExchangeRequest.getRequestedTokenType());
        putIfPresent(form, "actor_token", tokenExchangeRequest.getActorToken());
        putIfPresent(form, "actor_token_type", tokenExchangeRequest.getActorTokenType());
        return form;
    }

    /**
     * Authenticates the client either with the configured authorization header or, as a fallback, with the
     * {@code client_id} / {@code client_secret} form parameters described by RFC 6749 section 2.3.1.
     */
    private void applyClientAuthentication(RequestOptions reqOptions, Map<String, String> form) {
        String clientId = configuration().getClientId();
        String clientSecret = configuration().getClientSecret();

        if (isBlank(clientId) || isBlank(clientSecret)) {
            return;
        }

        if (configuration().isUseClientAuthorizationHeader()) {
            reqOptions.putHeader(configuration().getClientAuthorizationHeaderName(), clientAuthorizationHeaderValue());
        } else {
            form.put("client_id", clientId);
            form.put("client_secret", clientSecret);
        }
    }

    private static String encodeForm(Map<String, String> form) {
        return form
            .entrySet()
            .stream()
            .map(
                entry ->
                    URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8) +
                    '=' +
                    URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8)
            )
            .collect(Collectors.joining("&"));
    }

    /**
     * Builds the client authorization header value shared by introspection and token exchange, e.g.
     * {@code Basic base64(clientId:clientSecret)}.
     */
    private String clientAuthorizationHeaderValue() {
        return (
            configuration().getClientAuthorizationHeaderScheme().trim() +
            AUTHORIZATION_HEADER_SCHEME_SEPARATOR +
            Base64.getEncoder().encodeToString(
                (configuration().getClientId() + AUTHORIZATION_HEADER_VALUE_BASE64_SEPARATOR + configuration().getClientSecret()).getBytes(
                    StandardCharsets.UTF_8
                )
            )
        );
    }

    /**
     * Surfaces the OAuth error returned by the authorization server (RFC 6749 section 5.2, referenced by
     * RFC 8693 section 2.2.2) instead of a generic failure, so a misconfigured exchange can be diagnosed
     * from the policy error without reading the gateway logs.
     */
    private void handleTokenExchangeError(int statusCode, String body, Handler<TokenExchangeResponse> responseHandler) {
        String detail = null;
        try {
            JsonNode payload = MAPPER.readTree(body);
            String error = payload.path("error").asText(null);
            if (error != null) {
                String description = payload.path("error_description").asText(null);
                detail = description != null ? error + ": " + description : error;
            }
        } catch (IOException e) {
            log.debug("Token exchange error response is not a valid JSON payload", e);
        }

        String message = detail != null
            ? ERROR_EXCHANGING_TOKEN + " (" + statusCode + " " + detail + ")"
            : ERROR_EXCHANGING_TOKEN + " (" + statusCode + ")";

        log.error("An error occurs while exchanging token. Request ends with status {}: {}", statusCode, detail);
        responseHandler.handle(new TokenExchangeResponse(new OAuth2ResourceException(message)));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private void handleTokenExchangeSuccess(String body, Handler<TokenExchangeResponse> responseHandler) {
        try {
            JsonNode payload = MAPPER.readTree(body);
            // RFC 8693 section 2.2.1: access_token, issued_token_type and token_type are all REQUIRED
            for (String field : REQUIRED_TOKEN_EXCHANGE_FIELDS) {
                if (payload.path(field).asText(null) == null || payload.path(field).asText().isBlank()) {
                    responseHandler.handle(
                        new TokenExchangeResponse(new OAuth2ResourceException("Token exchange response does not contain " + field))
                    );
                    return;
                }
            }
            TokenExchangeResponse.Builder responseBuilder = TokenExchangeResponse.builder(
                payload.path("access_token").asText(),
                payload.path("issued_token_type").asText(),
                payload.path("token_type").asText()
            );
            if (payload.hasNonNull("expires_in")) {
                responseBuilder.expiresIn(payload.path("expires_in").asLong());
            }
            if (payload.hasNonNull("scope")) {
                responseBuilder.scope(payload.path("scope").asText());
            }
            if (payload.hasNonNull("refresh_token")) {
                responseBuilder.refreshToken(payload.path("refresh_token").asText());
            }
            responseHandler.handle(responseBuilder.build());
        } catch (IOException e) {
            // the body is the token payload: never log it
            log.error("Unable to parse token exchange response", e);
            responseHandler.handle(new TokenExchangeResponse(e));
        }
    }

    /**
     * Resolves the token exchange endpoint the same way introspection and userinfo are resolved: a path when an
     * authorization server URL is configured, otherwise the value as an absolute URL. Either way it must land on the
     * server the shared HTTP client was built for, since that client alone carries the configured TLS and proxy
     * settings; anything else is refused here, at start, rather than failing on the first exchange.
     *
     * @return the absolute endpoint, or {@code null} when token exchange is not configured
     */
    private static String resolveTokenExchangeEndpoint(String tokenExchangeEndpoint, String authorizationServerUrl, URL target) {
        if (tokenExchangeEndpoint == null || tokenExchangeEndpoint.isBlank()) {
            return null;
        }

        String endpoint = tokenExchangeEndpoint.trim();
        if (authorizationServerUrl != null && !authorizationServerUrl.isEmpty()) {
            endpoint = DUPLICATE_SLASH_REMOVER.matcher(authorizationServerUrl + '/' + endpoint).replaceAll("/");
        }

        final URI uri;
        try {
            uri = URI.create(endpoint);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("tokenExchangeEndpoint is not a valid URL: [" + endpoint + "]", e);
        }

        if (uri.getScheme() == null || uri.getHost() == null) {
            throw new IllegalArgumentException(
                "tokenExchangeEndpoint [" +
                    endpoint +
                    "] must be a path resolved against authorizationServerUrl, or an absolute URL on the authorization server"
            );
        }

        int port = uri.getPort() != -1 ? uri.getPort() : (HTTPS_SCHEME.equals(uri.getScheme()) ? 443 : 80);
        boolean sameServer =
            uri.getScheme().equalsIgnoreCase(target.getProtocol()) &&
            uri.getHost().equalsIgnoreCase(target.getHost()) &&
            port == target.getPort();
        if (!sameServer) {
            throw new IllegalArgumentException(
                "tokenExchangeEndpoint [" +
                    endpoint +
                    "] must be on the authorization server [" +
                    target +
                    "]: the resource's TLS and proxy settings only apply to that server"
            );
        }
        return endpoint;
    }

    private static void putIfPresent(Map<String, String> form, String key, String value) {
        if (value != null && !value.isBlank()) {
            form.put(key, value);
        }
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
    public OAuth2ResourceMetadata getProtectedResourceMetadata(String protectedResourceUri, List<String> scopesSupported) {
        String authServerMetadataEndpoint = configuration.getAuthorizationServerMetadataEndpoint();
        String authServerEndpoint = authServerMetadataEndpoint.substring(0, authServerMetadataEndpoint.lastIndexOf("/.well-known/"));
        URI authServerUri = URI.create(configuration.getAuthorizationServerUrl() + authServerEndpoint);
        String authorizationServer = authServerUri.normalize().toString();
        return new OAuth2ResourceMetadata(protectedResourceUri, List.of(authorizationServer), scopesSupported);
    }
}
