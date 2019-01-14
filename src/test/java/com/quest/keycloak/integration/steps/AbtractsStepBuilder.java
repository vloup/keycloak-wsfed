package com.quest.keycloak.integration.steps;

import com.quest.keycloak.integration.WsFedClient;
import com.quest.keycloak.integration.WsFedClientBuilder;
import org.jboss.logging.Logger;
import org.keycloak.testsuite.util.saml.SamlDocumentStepBuilder;

/** Inspired from the parent project https://github.com/keycloak/keycloak */
public abstract class AbtractsStepBuilder<T extends AbtractsStepBuilder<T>> implements WsFedClient.Step {

    private static final Logger LOG = Logger.getLogger(SamlDocumentStepBuilder.class);

    private final WsFedClientBuilder clientBuilder;

    public AbtractsStepBuilder(WsFedClientBuilder clientBuilder) {
        this.clientBuilder = clientBuilder;
    }

    public WsFedClientBuilder build() {
        return this.clientBuilder;
    }

}
