package com.quest.keycloak.integration;

import com.quest.keycloak.protocol.wsfed.WSFedLoginProtocolFactory;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Before;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.keycloak.testsuite.AbstractKeycloakTest;

import java.io.File;
import java.util.List;

import static org.keycloak.representations.idm.CredentialRepresentation.PASSWORD;
import static org.keycloak.testsuite.admin.Users.setPasswordFor;
import static org.keycloak.testsuite.utils.io.IOUtil.loadRealm;

public abstract class AbstractWsFedAuthTest extends AbstractKeycloakTest {

    public UserRepresentation bburkeUser;

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        testRealms.add(loadRealm("/realm-test-wsfed.json"));
    }

    @Deployment
    public static WebArchive deploy() {
        return ShrinkWrap.create(WebArchive.class, "run-on-server-classes.war")
                .addPackages(true, "com.quest.keycloak")
                .addAsManifestResource(new File("src/test/resources", "manifest.xml"))
                .addAsServiceProvider(RealmResourceProviderFactory.class, WSFedLoginProtocolFactory.class);
    }


    @Before
    public void beforeAuthTest() {
        bburkeUser = createUserRepresentation("bburke", "bburke@redhat.com", "Bill", "Burke", true);
        setPasswordFor(bburkeUser, PASSWORD);
    }

    public static UserRepresentation createUserRepresentation(String username, String email, String firstName, String lastName, boolean enabled) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEnabled(enabled);
        return user;
    }


}
