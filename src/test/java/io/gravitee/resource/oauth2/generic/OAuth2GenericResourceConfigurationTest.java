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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Fail.fail;

import io.gravitee.el.TemplateEngine;
import io.gravitee.el.spel.context.SecuredResolver;
import io.gravitee.plugin.configurations.http.HttpClientOptions;
import io.gravitee.plugin.configurations.http.HttpProxyOptions;
import io.gravitee.plugin.configurations.ssl.SslOptions;
import io.gravitee.resource.api.ResourceConfiguration;
import io.gravitee.resource.oauth2.generic.configuration.OAuth2ResourceConfiguration;
import io.gravitee.secrets.api.el.DelegatingEvaluatedSecretsMethods;
import io.gravitee.secrets.api.el.EvaluatedSecretsMethods;
import io.gravitee.secrets.api.el.FieldKind;
import io.gravitee.secrets.api.el.SecretFieldAccessControl;
import io.vertx.rxjava3.core.Vertx;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationContext;

/**
 * @author Benoit BORDIGONI (benoit.bordigoni at graviteesource.com)
 * @author GraviteeSource Team
 */
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
@ExtendWith(MockitoExtension.class)
class OAuth2GenericResourceConfigurationTest {

    @Mock
    private ApplicationContext applicationContext;

    private static TemplateEngine templateEngine;
    private List<SecretFieldAccessControl> recordedSecretFieldAccessControls = new ArrayList<>();

    @BeforeAll
    static void init() {
        SecuredResolver.initialize(null);
        templateEngine = TemplateEngine.templateEngine();
    }

    @BeforeEach
    void before() {
        EvaluatedSecretsMethods delegate = new EvaluatedSecretsMethods() {
            @Override
            public String fromGrant(String secretValue, SecretFieldAccessControl secretFieldAccessControl) {
                recordedSecretFieldAccessControls.add(secretFieldAccessControl);
                return secretValue;
            }

            @Override
            public String fromGrant(String contextId, String secretKey, SecretFieldAccessControl secretFieldAccessControl) {
                return fromGrant(contextId, secretFieldAccessControl);
            }

            @Override
            public String fromEL(String contextId, String uriOrName, SecretFieldAccessControl secretFieldAccessControl) {
                return fromGrant(contextId, secretFieldAccessControl);
            }
        };
        templateEngine.getTemplateContext().setVariable("secrets", new DelegatingEvaluatedSecretsMethods(delegate));
        templateEngine.getTemplateContext().setVariable("host", "acme.com");
        templateEngine.getTemplateContext().setVariable("masterId", "r2d2");
        Mockito.when(applicationContext.getBean(Vertx.class)).thenReturn(Vertx.vertx());
    }

    @Test
    void should_eval_config() throws Exception {
        OAuth2ResourceConfiguration config = new OAuth2ResourceConfiguration();
        config.setAuthorizationServerUrl("http://localhost:8080/auth");
        config.setClientId(asSecretEL("that is an ID"));
        config.setClientSecret(asSecretEL("that is a secret"));
        OAuth2GenericResource oAuth2GenericResource = underTest(config);
        oAuth2GenericResource.start();

        assertThat(oAuth2GenericResource.configuration().getClientId()).isEqualTo("that is an ID");
        assertThat(oAuth2GenericResource.configuration().getClientSecret()).isEqualTo("that is a secret");

        assertThat(recordedSecretFieldAccessControls).containsExactlyInAnyOrder(
            new SecretFieldAccessControl(true, FieldKind.GENERIC, "clientSecret"),
            new SecretFieldAccessControl(true, FieldKind.GENERIC, "clientId")
        );
    }

    @Test
    void should_not_be_able_to_resolve_secret_on_non_sensitive_field() throws Exception {
        OAuth2ResourceConfiguration config = new OAuth2ResourceConfiguration();
        config.setAuthorizationServerUrl("http://localhost:8080/auth");
        config.setClientAuthorizationHeaderName(asSecretEL("X-Test"));
        OAuth2GenericResource oAuth2GenericResource = underTest(config);
        oAuth2GenericResource.start();
        assertThat(recordedSecretFieldAccessControls).containsExactlyInAnyOrder(new SecretFieldAccessControl(false, null, null));
    }

    private static String asSecretEL(String password) {
        return "{#secrets.fromGrant('%s', #%s)}".formatted(password, SecretFieldAccessControl.EL_VARIABLE);
    }

    OAuth2GenericResource underTest(OAuth2ResourceConfiguration config) throws IllegalAccessException {
        OAuth2GenericResource redisCacheResource = new OAuth2GenericResource();
        Optional<Field> configuration = Stream.of(redisCacheResource.getClass().getSuperclass().getSuperclass().getDeclaredFields())
            .filter(field -> field.getName().equals("configuration") && field.getType().equals(ResourceConfiguration.class))
            .findFirst();
        if (configuration.isPresent()) {
            Field field = configuration.get();
            field.setAccessible(true);
            field.set(redisCacheResource, config);
        } else {
            fail("configuration field not found");
        }
        redisCacheResource.setDeploymentContext(new TestDeploymentContext(templateEngine));
        redisCacheResource.setApplicationContext(applicationContext);
        return redisCacheResource;
    }
}
