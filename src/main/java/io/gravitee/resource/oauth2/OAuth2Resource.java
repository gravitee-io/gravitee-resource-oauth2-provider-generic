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
package io.gravitee.resource.oauth2;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.oauth2.configuration.OAuth2ResourceConfiguration;
import org.asynchttpclient.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public class OAuth2Resource extends AbstractConfigurableResource<OAuth2ResourceConfiguration> {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2Resource.class);

    private AsyncHttpClient client;

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        DefaultAsyncHttpClientConfig.Builder builder = new DefaultAsyncHttpClientConfig.Builder();
        builder.setAcceptAnyCertificate(true);
        AsyncHttpClientConfig cf = builder.build();
        client = new DefaultAsyncHttpClient(cf);
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        if (client != null) {
            client.close();
        }
    }

    public void validate(String accessToken, Handler<OAuth2Response> responseHandler) {
        Map<String, Collection<String>> headers = new HashMap<>();
        Map<String, List<String>> queryParams = new HashMap<>();

        headers.put(configuration().getAuthorizationHeaderName(),
                Collections.singletonList(configuration().getAuthorizationScheme().trim() + " " + configuration().getAuthorizationValue()));

        if (configuration().isTokenIsSuppliedByQueryParam()) {
            queryParams.put(configuration().getTokenQueryParamName(), Collections.singletonList(accessToken));
        } else if (configuration().isTokenIsSuppliedByHttpHeader()) {
            headers.put(configuration().getTokenHeaderName(), Collections.singletonList(accessToken));
        }

        RequestBuilder builder = new RequestBuilder();
        builder.setUrl(configuration().getServerURL());
        builder.setMethod(configuration().getHttpMethod());
        builder.setHeaders(headers);
        builder.setQueryParams(queryParams);

        client.executeRequest(builder.build(), new AsyncCompletionHandler<Void>() {
            @Override
            public Void onCompleted(org.asynchttpclient.Response clientResponse) throws Exception {
                if (clientResponse.getStatusCode() == HttpStatusCode.OK_200) {
                    handleResponse(new OAuth2Response(true, clientResponse.getResponseBody()));
                } else {
                    handleResponse(new OAuth2Response(false, clientResponse.getResponseBody()));
                }
                return null;
            }

            @Override
            public void onThrowable(Throwable t) {
                LOGGER.warn("Unexpected error while invoking remote OAuth2 Authorization server at {}", configuration().getServerURL(), t);
                handleResponse(new OAuth2Response(t));
            }

            private void handleResponse(OAuth2Response oAuth2Response) {
                responseHandler.handle(oAuth2Response);
            }
        });
    }
}
