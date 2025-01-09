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
package io.gravitee.resource.oauth2.generic.configuration;

import io.gravitee.plugin.annotation.ConfigurationEvaluator;
import io.gravitee.resource.api.ResourceConfiguration;
import io.gravitee.secrets.api.annotation.Secret;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@ConfigurationEvaluator
@Data
public class OAuth2ResourceConfiguration implements ResourceConfiguration {

    private String authorizationServerUrl;
    private String introspectionEndpoint;
    private boolean useSystemProxy;

    @Pattern(regexp = "GET|POST")
    private String introspectionEndpointMethod;

    private String userInfoEndpoint;
    private String userInfoEndpointMethod;

    @Secret
    private String clientId;

    @Secret
    private String clientSecret;

    private boolean useClientAuthorizationHeader;
    private String clientAuthorizationHeaderName;
    private String clientAuthorizationHeaderScheme;
    private boolean tokenIsSuppliedByQueryParam;
    private String tokenQueryParamName;
    private boolean tokenIsSuppliedByHttpHeader;
    private String tokenHeaderName;
    private boolean tokenIsSuppliedByFormUrlEncoded;
    private String tokenFormUrlEncodedName;
    private String scopeSeparator;
    private String userClaim;
}
