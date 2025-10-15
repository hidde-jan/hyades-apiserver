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
package org.dependencytrack.persistence;

import alpine.persistence.PaginatedResult;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.CsafDocumentEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.jdbi.AdvisoryDao;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

public class AdvisoriesQueryManagerTest extends PersistenceCapableTest {

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
        PaginatedResult result = qm.getAdvisories();
        Assert.assertEquals(2, result.getTotal());
        List<AdvisoryDao.AdvisoriesPortfolioRow> advisories = result.getList(AdvisoryDao.AdvisoriesPortfolioRow.class);
        Assert.assertEquals(2, advisories.size());
        Assert.assertEquals("CSAF-1", advisories.getFirst().name());
        Assert.assertEquals(1, advisories.getFirst().affectedProjects());
    }

    @Test
    public void getAdvisoryByIdTest() {
        SampleData sampleData = new SampleData();
        AdvisoryDao.AdvisoryResult result = qm.getAdvisoryById(sampleData.adv1.getId());
        Assert.assertNotNull(result);
        Assert.assertEquals("CSAF-1", result.entity().getName());
        Assert.assertEquals(1, result.affectedProjects().size());
        Assert.assertEquals("Project 1", result.affectedProjects().getFirst().name());
        Assert.assertEquals(1, result.vulnerabilities().size());
        Assert.assertEquals("INT-1", result.vulnerabilities().getFirst().vulnId());
    }

    @Test
    public void getAdvisoriesByProjectTest() {
        SampleData sampleData = new SampleData();
        PaginatedResult result = qm.getAdvisoriesByProject(sampleData.p1.getId(), false);
        Assert.assertEquals(1, result.getTotal());
        List<AdvisoryDao.AdvisoryRow> advisories = result.getList(AdvisoryDao.AdvisoryRow.class);
        Assert.assertEquals(1, advisories.size());
        Assert.assertEquals("CSAF-1", advisories.getFirst().name());
    }

    @Test
    public void getFindingsByProjectAdvisoryTest() {
        SampleData sampleData = new SampleData();
        PaginatedResult result = qm.getFindingsByProjectAdvisory(sampleData.p1.getId(), sampleData.adv1.getId());
        Assert.assertEquals(1, result.getTotal());
        List<AdvisoryDao.ProjectAdvisoryFinding> findings = result.getList(AdvisoryDao.ProjectAdvisoryFinding.class);
        Assert.assertEquals(1, findings.size());
        Assert.assertEquals("Component 1", findings.getFirst().name());
    }
}
