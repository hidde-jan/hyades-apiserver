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
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.CsafDocumentEntity;
import org.dependencytrack.persistence.jdbi.AdvisoryDao;

import javax.jdo.PersistenceManager;
import java.util.List;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

final class AdvisoriesQueryManager extends QueryManager implements IQueryManager {

    AdvisoriesQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    AdvisoriesQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    public PaginatedResult getAdvisories() {
        final List<AdvisoryDao.AdvisoriesPortfolioRow> advisoryRows = withJdbiHandle(this.request, handle ->
                handle.attach(AdvisoryDao.class).getAllAdvisories());
        final long totalCount = advisoryRows.isEmpty() ? 0 : advisoryRows.get(0).totalCount();
        final PaginatedResult result = new PaginatedResult();
        result.setObjects(advisoryRows);
        result.setTotal(totalCount);
        return result;
    }

    public AdvisoryDao.AdvisoryResult getAdvisoryById(long advisoryId) {
        final var advisoryEntity = getObjectById(CsafDocumentEntity.class, advisoryId);
        if (advisoryEntity == null) {
            return null;
        }

        List<AdvisoryDao.ProjectRow> affectedProjects = withJdbiHandle(this.request, handle ->
                handle.attach(AdvisoryDao.class).getProjectsByAdvisory(advisoryEntity.getId()));

        List<AdvisoryDao.VulnerabilityRow> vulnerabilities = withJdbiHandle(this.request, handle ->
                handle.attach(AdvisoryDao.class).getVulnerabilitiesByAdvisory(advisoryEntity.getId()));

        return new AdvisoryDao.AdvisoryResult(
                advisoryEntity,
                affectedProjects,
                vulnerabilities
        );
    }

    public PaginatedResult getAdvisoriesByProject(long projectId, boolean suppressed) {
        final List<AdvisoryDao.AdvisoryRow> advisoryRows = withJdbiHandle(this.request, handle ->
                handle.attach(AdvisoryDao.class).getAdvisoriesByProject(projectId, suppressed));
        final long totalCount = advisoryRows.isEmpty() ? 0 : advisoryRows.get(0).totalCount();
        final PaginatedResult result = new PaginatedResult();
        result.setObjects(advisoryRows);
        result.setTotal(totalCount);
        return result;
    }

    public PaginatedResult getFindingsByProjectAdvisory(long projectId, long advisoryId) {
        final List<AdvisoryDao.ProjectAdvisoryFinding> advisoryRows = withJdbiHandle(this.request, handle ->
                handle.attach(AdvisoryDao.class).getFindingsByProjectAdvisory(projectId, advisoryId));
        final long totalCount = advisoryRows.isEmpty() ? 0 : advisoryRows.get(0).totalCount();
        final PaginatedResult result = new PaginatedResult();
        result.setObjects(advisoryRows);
        result.setTotal(totalCount);
        return result;
    }
}
