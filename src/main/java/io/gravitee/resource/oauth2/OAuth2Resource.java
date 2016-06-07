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

import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.oauth2.configuration.OAuth2ResourceConfiguration;
import org.asynchttpclient.*;

/**
 * @author David BRASSELY (david at gravitee.io)
 * @author GraviteeSource Team
 */
public class OAuth2Resource extends AbstractConfigurableResource<OAuth2ResourceConfiguration> {

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

    public void validateToken(OAuth2Request request,
                              AsyncHandler responseHandler) {
        RequestBuilder builder = new RequestBuilder();
        builder.setUrl(configuration().getServerURL());
        builder.setMethod(configuration().getHttpMethod());
        builder.setHeaders(request.getHeaders());
        builder.setQueryParams(request.getQueryParams());

        client.executeRequest(builder.build(), responseHandler);
    }
}
