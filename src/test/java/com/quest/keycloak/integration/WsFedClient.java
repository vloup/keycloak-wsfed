package com.quest.keycloak.integration;

import org.apache.http.NameValuePair;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.jboss.logging.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.saml.SAMLRequestParser;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.processing.api.saml.v2.request.SAML2Request;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class WsFedClient {

    @FunctionalInterface
    public interface Step {
        HttpUriRequest perform(CloseableHttpClient client, URI currentURI, CloseableHttpResponse currentResponse, HttpClientContext context) throws Exception;
    }

    @FunctionalInterface
    public interface ResultExtractor<T> {
        T extract(CloseableHttpResponse response) throws Exception;
    }

    public static final class DoNotFollowRedirectStep implements Step {

        @Override
        public HttpUriRequest perform(CloseableHttpClient client, URI uri, CloseableHttpResponse response, HttpClientContext context) throws Exception {
            return null;
        }
    }

    public static class RedirectStrategyWithSwitchableFollowRedirect extends LaxRedirectStrategy {

        public boolean redirectable = true;

        @Override
        protected boolean isRedirectable(String method) {
            return redirectable && super.isRedirectable(method);
        }

        public void setRedirectable(boolean redirectable) {
            this.redirectable = redirectable;
        }
    }

    private static final Logger LOG = Logger.getLogger(WsFedClient.class);

    private final HttpClientContext context = HttpClientContext.create();

    private final RedirectStrategyWithSwitchableFollowRedirect strategy = new RedirectStrategyWithSwitchableFollowRedirect();

    /**
     * Extracts and parses value of SAMLResponse input field of a form present in the given page.
     *
     * @param responsePage HTML code of the page
     * @return
     */
    public static SAMLDocumentHolder extractSamlResponseFromForm(String responsePage) {
        org.jsoup.nodes.Document theResponsePage = Jsoup.parse(responsePage);
        Elements samlResponses = theResponsePage.select("input[name=SAMLResponse]");
        Elements samlRequests = theResponsePage.select("input[name=SAMLRequest]");
        int size = samlResponses.size() + samlRequests.size();
        assertThat("Checking uniqueness of SAMLResponse/SAMLRequest input field in the page", size, is(1));

        Element respElement = samlResponses.isEmpty() ? samlRequests.first() : samlResponses.first();

        return SAMLRequestParser.parseResponsePostBinding(respElement.val());
    }

    /**
     * Extracts and parses value of SAMLResponse query parameter from the given URI.
     *
     * @param responseUri
     * @return
     */
    public static SAMLDocumentHolder extractSamlResponseFromRedirect(String responseUri) {
        List<NameValuePair> params = URLEncodedUtils.parse(URI.create(responseUri).toString(), Charset.forName("UTF-8"));

        String samlDoc = null;
        for (NameValuePair param : params) {
            if ("SAMLResponse".equals(param.getName()) || "SAMLRequest".equals(param.getName())) {
                assertThat("Only one SAMLRequest/SAMLResponse check", samlDoc, nullValue());
                samlDoc = param.getValue();
            }
        }

        return SAMLRequestParser.parseResponseRedirectBinding(samlDoc);
    }

    /**
     * Creates a SAML login request document with the given parameters. See SAML &lt;AuthnRequest&gt; description for more details.
     *
     * @param issuer
     * @param assertionConsumerURL
     * @param destination
     * @return
     */
    public static AuthnRequestType createLoginRequestDocument(String issuer, String assertionConsumerURL, URI destination) {
        try {
            SAML2Request samlReq = new SAML2Request();
            AuthnRequestType loginReq = samlReq.createAuthnRequestType(UUID.randomUUID().toString(), assertionConsumerURL,
                    destination == null ? null : destination.toString(), issuer);

            return loginReq;
        } catch (ConfigurationException ex) {
            throw new RuntimeException(ex);
        }
    }

    public void execute(Step... steps) {
        executeAndTransform(resp -> null, Arrays.asList(steps));
    }

    public void execute(List<Step> steps) {
        executeAndTransform(resp -> null, steps);
    }

    public <T> T executeAndTransform(ResultExtractor<T> resultTransformer, Step... steps) {
        return executeAndTransform(resultTransformer, Arrays.asList(steps));
    }

    public <T> T executeAndTransform(ResultExtractor<T> resultTransformer, List<Step> steps) {
        CloseableHttpResponse currentResponse = null;
        URI currentUri = URI.create("about:blank");
        strategy.setRedirectable(true);

        try (CloseableHttpClient client = createHttpClientBuilderInstance().setRedirectStrategy(strategy).build()) {
            for (int i = 0; i < steps.size(); i ++) {
                Step s = steps.get(i);
                LOG.infof("Running step %d: %s", i, s.getClass());

                CloseableHttpResponse origResponse = currentResponse;

                HttpUriRequest request = s.perform(client, currentUri, origResponse, context);
                if (request == null) {
                    LOG.info("Last step returned no request, continuing with next step.");
                    continue;
                }

                // Setting of follow redirects has to be set before executing the final request of the current step
                if (i < steps.size() - 1 && steps.get(i + 1) instanceof DoNotFollowRedirectStep) {
                    LOG.debugf("Disabling following redirects");
                    strategy.setRedirectable(false);
                    i++;
                } else {
                    strategy.setRedirectable(true);
                }

                LOG.infof("Executing HTTP request to %s", request.getURI());
                currentResponse = client.execute(request, context);

                currentUri = request.getURI();
                List<URI> locations = context.getRedirectLocations();
                if (locations != null && ! locations.isEmpty()) {
                    currentUri = locations.get(locations.size() - 1);
                }

                LOG.infof("Landed to %s", currentUri);

                if (currentResponse != origResponse && origResponse != null) {
                    origResponse.close();
                }
            }

            LOG.info("Going to extract response");

            return resultTransformer.extract(currentResponse);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public HttpClientContext getContext() {
        return context;
    }

    protected HttpClientBuilder createHttpClientBuilderInstance() {
        return HttpClientBuilder.create();
    }
}
