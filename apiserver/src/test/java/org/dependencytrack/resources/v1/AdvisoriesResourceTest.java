/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.CsafDocumentEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.ws.rs.core.Response;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;

public class AdvisoriesResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(AdvisoriesResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class));

    private class SampleData {
        final Project p1;
        final Component c1;
        final Vulnerability v1;
        final CsafDocumentEntity adv1;
        final CsafDocumentEntity adv2;

        SampleData() {
            p1 = qm.createProject("Project 1", null, "1.0", null, null, null, null, false);
            c1 = new Component();
            c1.setProject(p1);
            c1.setName("Component 1");
            qm.createComponent(c1, false);

            v1 = new Vulnerability();
            v1.setVulnId("INT-1");
            v1.setSource(Vulnerability.Source.INTERNAL);
            v1.setSeverity(Severity.CRITICAL);
            qm.createVulnerability(v1, false);
            qm.addVulnerability(v1, c1, AnalyzerIdentity.NONE);

            adv1 = new CsafDocumentEntity();
            adv1.setName("CSAF-1");
            adv1.setPublisherNamespace("Foo");
            adv1.setTrackingID("Foo-123");
            adv1.setTrackingVersion("1.0.0");
            adv1.setUrl("https://example.com/csaf-1.json");
            qm.persist(adv1);

            adv2 = new CsafDocumentEntity();
            adv2.setName("CSAF-2");
            adv2.setPublisherNamespace("Bar");
            adv2.setTrackingID("Bar-456");
            adv2.setTrackingVersion("1.0.1");
            adv2.setUrl("https://example.com/csaf-2.json");
            qm.persist(adv2);

            qm.createCsafMapping(v1, adv1);
        }
    }

    @Test
    public void getAdvisoriesTest() {
        new SampleData();
        Response response = jersey.target(V1_ADVISORIES).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("2", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(2, json.size());
        Assert.assertEquals("CSAF-1", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getAdvisoryByIdTest() {
        SampleData sampleData = new SampleData();
        Response response = jersey.target(V1_ADVISORIES + "/" + sampleData.adv1.getId()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        assertThatJson(body).isObject().containsKeys("entity", "affectedProjects", "vulnerabilities");
        assertThatJson(body).node("entity.name").isEqualTo("CSAF-1");
        assertThatJson(body).node("affectedProjects[0].name").isEqualTo("Project 1");
        assertThatJson(body).node("vulnerabilities[0].vulnId").isEqualTo("INT-1");
    }

    @Test
    public void getAdvisoryByIdInvalidTest() {
        new SampleData();
        Response response = jersey.target(V1_ADVISORIES + "/999").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The requested CSAF document could not be found.", body);
    }

    @Test
    public void getAdvisoriesByProjectTest() {
        SampleData sampleData = new SampleData();
        Response response = jersey.target(V1_ADVISORIES + "/project/" + sampleData.p1.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1, json.size());
        Assert.assertEquals("CSAF-1", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getAdvisoriesByProjectInvalidTest() {
        new SampleData();
        Response response = jersey.target(V1_ADVISORIES + "/project/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        Assert.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }

    @Test
    public void getFindingsByProjectAdvisoryTest() {
        SampleData sampleData = new SampleData();
        Response response = jersey.target(V1_ADVISORIES + "/project/" + sampleData.p1.getUuid() + "/advisory/" + sampleData.adv1.getId()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(200, response.getStatus(), 0);
        Assert.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
        Assert.assertEquals(1, json.size());
        Assert.assertEquals("Component 1", json.getJsonObject(0).getString("name"));
    }

    @Test
    public void getFindingsByProjectAdvisoryInvalidProjectTest() {
        SampleData sampleData = new SampleData();
        Response response = jersey.target(V1_ADVISORIES + "/project/" + UUID.randomUUID() + "/advisory/" + sampleData.adv1.getId()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assert.assertEquals(404, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assert.assertEquals("The project could not be found.", body);
    }
}
