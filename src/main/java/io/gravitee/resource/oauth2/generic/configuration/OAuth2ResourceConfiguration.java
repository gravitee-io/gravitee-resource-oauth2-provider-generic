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
package io.gravitee.resource.oauth2.generic.configuration;

import io.gravitee.resource.api.ResourceConfiguration;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class OAuth2ResourceConfiguration implements ResourceConfiguration {

    private String introspectionEndpoint;

    private String introspectionEndpointMethod;

    private String clientId;

    private String clientSecret;

    private boolean useClientAuthorizationHeader;

    private String clientAuthorizationHeaderName;

    private String clientAuthorizationHeaderScheme;

    private boolean tokenIsSuppliedByQueryParam;

    private String tokenQueryParamName;

    private boolean tokenIsSuppliedByHttpHeader;

    private String tokenHeaderName;

    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    public void setIntrospectionEndpoint(String introspectionEndpoint) {
        this.introspectionEndpoint = introspectionEndpoint;
    }

    public String getIntrospectionEndpointMethod() {
        return introspectionEndpointMethod;
    }

    public void setIntrospectionEndpointMethod(String introspectionEndpointMethod) {
        this.introspectionEndpointMethod = introspectionEndpointMethod;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public boolean isUseClientAuthorizationHeader() {
        return useClientAuthorizationHeader;
    }

    public void setUseClientAuthorizationHeader(boolean useClientAuthorizationHeader) {
        this.useClientAuthorizationHeader = useClientAuthorizationHeader;
    }

    public String getClientAuthorizationHeaderName() {
        return clientAuthorizationHeaderName;
    }

    public void setClientAuthorizationHeaderName(String clientAuthorizationHeaderName) {
        this.clientAuthorizationHeaderName = clientAuthorizationHeaderName;
    }

    public String getClientAuthorizationHeaderScheme() {
        return clientAuthorizationHeaderScheme;
    }

    public void setClientAuthorizationHeaderScheme(String clientAuthorizationHeaderScheme) {
        this.clientAuthorizationHeaderScheme = clientAuthorizationHeaderScheme;
    }

    public boolean isTokenIsSuppliedByQueryParam() {
        return tokenIsSuppliedByQueryParam;
    }

    public void setTokenIsSuppliedByQueryParam(boolean tokenIsSuppliedByQueryParam) {
        this.tokenIsSuppliedByQueryParam = tokenIsSuppliedByQueryParam;
    }

    public String getTokenQueryParamName() {
        return tokenQueryParamName;
    }

    public void setTokenQueryParamName(String tokenQueryParamName) {
        this.tokenQueryParamName = tokenQueryParamName;
    }

    public boolean isTokenIsSuppliedByHttpHeader() {
        return tokenIsSuppliedByHttpHeader;
    }

    public void setTokenIsSuppliedByHttpHeader(boolean tokenIsSuppliedByHttpHeader) {
        this.tokenIsSuppliedByHttpHeader = tokenIsSuppliedByHttpHeader;
    }

    public String getTokenHeaderName() {
        return tokenHeaderName;
    }

    public void setTokenHeaderName(String tokenHeaderName) {
        this.tokenHeaderName = tokenHeaderName;
    }
}
