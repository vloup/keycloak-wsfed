package com.quest.keycloak.protocol.wsfed.mappers;

import com.quest.keycloak.broker.wsfed.mappers.UserAttributeMapper;
import com.quest.keycloak.protocol.wsfed.WSFedLoginProtocol;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SAMLAttributeNamespaceMapper extends AbstractWsfedProtocolMapper {

    public static final String PROVIDER_ID = "wsfed-saml-attribute-namespace-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(AttributeStatementHelper.SAML_ATTRIBUTE_NAME);
        property.setLabel("SAML Attribute Namespace");
        property.setHelpText("Namespace to use for SAML 1.1 Assertions");
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(AttributeStatementHelper.FRIENDLY_NAME);
        property.setLabel(AttributeStatementHelper.FRIENDLY_NAME_LABEL);
        property.setHelpText(AttributeStatementHelper.FRIENDLY_NAME_HELP_TEXT);
        configProperties.add(property);
    }

    @Override
    public String getDisplayCategory() {
        return SAML11_NAMESPACE_MAPPER;
    }

    @Override
    public String getDisplayType() {
        return "SAML 1.1 Attribute Namespace";
    }

    @Override
    public String getHelpText() {
        return "Map Attribute Namespace to SAML";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * Creates a protocol mapper model for this URI Namespace Attribute Mapper. This mapper model is meant to be used for
     * testing, as normally such objects are created in a different manner through the keycloak GUI.
     *
     * @param name The name of the mapper (this has no functional use)
     * @param samlAttributeNamespace The name of the attribute in the SAML attribute
     * @param friendlyName a display name, only useful for the keycloak GUI
     * @return a Protocol Mapper for a group mapping
     */
    public static ProtocolMapperModel create(String name, String samlAttributeNamespace, String friendlyName) {
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setName(name);
        Map<String, String> config = new HashMap<String, String>();
        config.put(AttributeStatementHelper.SAML_ATTRIBUTE_NAME, samlAttributeNamespace);
        if (friendlyName != null) {
            config.put(AttributeStatementHelper.FRIENDLY_NAME, friendlyName);
        }
        model.setConfig(config);
        model.setProtocolMapper(PROVIDER_ID);
        model.setProtocol(WSFedLoginProtocol.LOGIN_PROTOCOL);
        return model;
    }
}
