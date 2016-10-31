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
package io.gravitee.resource.oauth2.configuration;

import io.gravitee.resource.api.ResourceConfiguration;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class OAuth2ResourceConfiguration implements ResourceConfiguration {

    private String serverURL;

    private String httpMethod;

    private boolean secure;

    private String authorizationHeaderName;

    private String authorizationScheme;

    private String authorizationValue;

    private boolean tokenIsSuppliedByQueryParam;

    private String tokenQueryParamName;

    private boolean tokenIsSuppliedByHttpHeader;

    private String tokenHeaderName;

    public String getAuthorizationHeaderName() {
        return authorizationHeaderName;
    }

    public void setAuthorizationHeaderName(String authorizationHeaderName) {
        this.authorizationHeaderName = authorizationHeaderName;
    }

    public String getAuthorizationScheme() {
        return authorizationScheme;
    }

    public void setAuthorizationScheme(String authorizationScheme) {
        this.authorizationScheme = authorizationScheme;
    }

    public String getAuthorizationValue() {
        return authorizationValue;
    }

    public void setAuthorizationValue(String authorizationValue) {
        this.authorizationValue = authorizationValue;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    public String getServerURL() {
        return serverURL;
    }

    public void setServerURL(String serverURL) {
        this.serverURL = serverURL;
    }

    public String getTokenHeaderName() {
        return tokenHeaderName;
    }

    public void setTokenHeaderName(String tokenHeaderName) {
        this.tokenHeaderName = tokenHeaderName;
    }

    public boolean isTokenIsSuppliedByHttpHeader() {
        return tokenIsSuppliedByHttpHeader;
    }

    public void setTokenIsSuppliedByHttpHeader(boolean tokenIsSuppliedByHttpHeader) {
        this.tokenIsSuppliedByHttpHeader = tokenIsSuppliedByHttpHeader;
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
}
