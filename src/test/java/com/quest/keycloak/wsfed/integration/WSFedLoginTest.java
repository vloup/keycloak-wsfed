package com.quest.keycloak.wsfed.integration;

import com.quest.keycloak.broker.wsfed.WSFedIdentityProviderFactory;
import com.quest.keycloak.broker.wsfed.mappers.AttributeToRoleMapper;
import com.quest.keycloak.broker.wsfed.mappers.UserAttributeMapper;
import com.quest.keycloak.protocol.wsfed.WSFedLoginProtocolFactory;
import com.quest.keycloak.protocol.wsfed.installation.WSFedIDPDescriptorClientInstallation;
import com.quest.keycloak.protocol.wsfed.mappers.*;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.jboss.shrinkwrap.resolver.api.maven.ScopeType;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.protocol.ClientInstallationProvider;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.test.TestsHelper;

import javax.ws.rs.core.Response;
import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.util.Arrays;

@RunWith(Arquillian.class)
@RunAsClient
public class WSFedLoginTest {

    private static final String MODULE_JAR = "keycloak-wsfed";
    private static final String CLIENT = "wsfed";
    private static final String SECRET = "**********";
    private static final String TEST_REALM_NAME = "wsfed-idp-test";

    @BeforeClass
    public static void initRealmAndUsers() throws IOException {
        TestsHelper.baseUrl=TestsHelper.keycloakBaseUrl;
        TestsHelper.importTestRealm("admin", "admin", "/"+TEST_REALM_NAME+"-realm.json");
    }

    @AfterClass
    public static void resetRealm() throws IOException {
        TestsHelper.deleteRealm("admin", "admin", TEST_REALM_NAME);
    }

    @Deployment(name=MODULE_JAR, testable = false)
    @TargetsContainer("keycloak-remote")
    public static Archive<?> createProviderArchive() throws IOException {
        File[] files = Maven.resolver()
                .loadPomFromFile("pom.xml")
                .importDependencies(ScopeType.PROVIDED)
                .resolve()
                .withTransitivity()
                .asFile();
        return ShrinkWrap.create(WebArchive.class, MODULE_JAR)
                .addPackages(true, "com.quest.keycloak")
                .addAsManifestResource(new File("src/test/resources", "MANIFEST.MF"))
                .addAsServiceProvider(IdentityProviderFactory.class, WSFedIdentityProviderFactory.class)
                .addAsServiceProvider(IdentityProviderMapper.class, AttributeToRoleMapper.class)
                .addAsServiceProvider(IdentityProviderMapper.class, UserAttributeMapper.class)
                .addAsServiceProvider(ClientInstallationProvider.class, WSFedIDPDescriptorClientInstallation.class)
                .addAsServiceProvider(LoginProtocolFactory.class, WSFedLoginProtocolFactory.class)
                .addAsServiceProvider(ProtocolMapper.class, OIDCAddressMapper.class)
                .addAsServiceProvider(ProtocolMapper.class, OIDCFullNameMapper.class)
                .addAsServiceProvider(ProtocolMapper.class, OIDCUserPropertyMapper.class)
                .addAsServiceProvider(ProtocolMapper.class, SAMLRoleListMapper.class)
                .addAsServiceProvider(ProtocolMapper.class, SAMLUserPropertyAttributeStatementMapper.class)
                .addAsServiceProvider(ProtocolMapper.class, SAMLUserAttributeStatementMapper.class)
                .addAsServiceProvider(ProtocolMapper.class, SAMLGroupMembershipMapper.class)
                .addAsLibraries(files)
                ;
    }

    @Test
    public void getInstallationDescriptor(){
        Keycloak keycloak = Keycloak.getInstance(TestsHelper.keycloakBaseUrl, "master", "admin", "admin", "admin-cli");
        ClientRepresentation client = keycloak.realm(TEST_REALM_NAME).clients().findByClientId(CLIENT).get(0);
        client.getBaseUrl();

//        TestsHelper.testGetWithAuth("/auth/admin/realms/wsfed-idp/clients/bf0bcab9-f4fe-4d8d-b867-fb1dd4cad258/installation/providers/wsfed-idp-descriptor")
    }
}
