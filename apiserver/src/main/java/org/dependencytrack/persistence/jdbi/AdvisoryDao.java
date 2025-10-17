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
package org.dependencytrack.persistence.jdbi;

import org.dependencytrack.model.CsafDocumentEntity;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.List;

/**
 * JDBI Data Access Object for performing operations on {@link CsafDocumentEntity} objects.
 */
public interface AdvisoryDao {

    record AdvisoryRow(
            String name,
            int projectId,
            String url,
            int documentId,
            int findingsPerDoc,
            long totalCount
    ) {
    }

    record VulnerabilityRow(
            String id,
            String source,
            String vulnId,
            long totalCount
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT "NAME" AS "name"
                 , "PROJECT_ID" AS "projectId"
                 , "URL" AS "url"
                 , "CSAFDOCUMENT_ID" AS "documentId"
                 , COUNT("FINDINGATTRIBUTION"."ID") AS "findingsPerDoc"
                 , COUNT(*) OVER() AS "totalCount"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "CSAFMAPPING"
               ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            WHERE "PROJECT_ID" = :projectId
            <#if apiFilterParameter??>
                AND LOWER("CSAFDOCUMENTENTITY"."NAME") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
            </#if>
            GROUP BY "CSAFDOCUMENT_ID", "NAME", "URL", "PROJECT_ID"
            
            <#if apiOrderByClause??>
                ${apiOrderByClause}
            <#else>
                ORDER BY "name" ASC
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.AdvisoryRow.class)
    @AllowApiOrdering(by = {
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "findingsPerDoc")
    })
    List<AdvisoryDao.AdvisoryRow> getAdvisoriesByProject(@Bind long projectId, @Bind boolean includeSuppressed);

    record AdvisoryResult(
            CsafDocumentEntity entity,
            List<ProjectRow> affectedProjects,
            long numAffectedComponents,
            List<AdvisoryDao.VulnerabilityRow> vulnerabilities
    ) {
    }

    record ProjectRow(
            int id,
            String name,
            String uuid,
            String desc,
            String version,
            long totalCount
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT DISTINCT "PROJECT_ID" AS "id",
            "PROJECT"."NAME" AS "name",
            "PROJECT"."UUID" AS "uuid",
            "PROJECT"."DESCRIPTION" AS "desc",
            "PROJECT"."VERSION" AS "version",
            COUNT(*) OVER() AS "totalCount"
            --Latest,Classifier,Last BOM Import,BOM Format,Risk Score,Active,Policy Violations,Vulnerabilities
            
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "CSAFMAPPING"
            ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            INNER JOIN "PROJECT" ON "PROJECT_ID" = "PROJECT"."ID"
            WHERE "CSAFDOCUMENT_ID" = :advisoryId
            <#if apiFilterParameter??>
                AND LOWER("PROJECT"."NAME") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
            </#if>
            
            <#if apiOrderByClause??>
                ${apiOrderByClause}
            <#else>
                ORDER BY "name" ASC
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.ProjectRow.class)
    @AllowApiOrdering(by = {
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "version")
    })
    List<ProjectRow> getProjectsByAdvisory(long advisoryId);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT DISTINCT "VULNERABILITY"."ID" AS "id",
            "SOURCE" AS "source",
            "VULNID" AS "vulnId",
            COUNT(*) OVER() AS "totalCount"
            
            FROM "CSAFMAPPING"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            INNER JOIN "VULNERABILITY" ON "CSAFMAPPING"."VULNERABILITY_ID" = "VULNERABILITY"."ID"
            WHERE "CSAFDOCUMENT_ID" = :advisoryId
            <#if apiFilterParameter??>
                AND LOWER("VULNERABILITY"."VULNID") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
            </#if>
            
            <#if apiOrderByClause??>
                ${apiOrderByClause}
            <#else>
                ORDER BY "vulnId" ASC
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.VulnerabilityRow.class)
    @AllowApiOrdering(by = {
            @AllowApiOrdering.Column(name = "vulnId"),
            @AllowApiOrdering.Column(name = "source")
    })
    List<VulnerabilityRow> getVulnerabilitiesByAdvisory(long advisoryId);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT COUNT(DISTINCT "FINDINGATTRIBUTION"."COMPONENT_ID") AS "findingsWithAnalysis"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "CSAFMAPPING"
            ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            INNER JOIN "ANALYSIS" ON
            "FINDINGATTRIBUTION"."PROJECT_ID" = "ANALYSIS"."PROJECT_ID"
            WHERE "CSAFDOCUMENT_ID" = :advisoryId
            GROUP BY "CSAFDOCUMENT_ID"
            
             ${apiOffsetLimitClause!}
            """)
    long getAmountFindingsMarked(long advisoryId);

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT COUNT(DISTINCT "FINDINGATTRIBUTION"."COMPONENT_ID") AS "findingsWithAnalysis"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "CSAFMAPPING"
            ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            WHERE "CSAFDOCUMENT_ID" = :advisoryId
            GROUP BY "CSAFDOCUMENT_ID"
            
             ${apiOffsetLimitClause!}
            """)
    long getAmountFindingsTotal(long advisoryId);

    record AdvisoriesPortfolioRow(
            String name,
            int affectedComponents,
            int affectedProjects,
            String url,
            int documentId,
            long totalCount
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->

            SELECT "CSAFDOCUMENTENTITY"."NAME" as "name",
            COUNT(DISTINCT "FINDINGATTRIBUTION"."COMPONENT_ID") AS "affectedComponents",
            COUNT(DISTINCT "PROJECT_ID") AS "affectedProjects",
            "URL" AS "url",
            "CSAFDOCUMENTENTITY"."ID" AS "documentId",
            COUNT(*) OVER() AS "totalCount"
            FROM "CSAFDOCUMENTENTITY"
            LEFT JOIN "CSAFMAPPING" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            LEFT JOIN "FINDINGATTRIBUTION" ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            <#if apiFilterParameter??>
            WHERE LOWER("CSAFDOCUMENTENTITY"."NAME") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
            </#if>
            GROUP BY "CSAFDOCUMENTENTITY"."ID","CSAFDOCUMENTENTITY"."NAME","URL"
            
            <#if apiOrderByClause??>
                ${apiOrderByClause}
            <#else>
                ORDER BY "name" ASC
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.AdvisoriesPortfolioRow.class)
    @AllowApiOrdering(by = {
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "affectedComponents"),
            @AllowApiOrdering.Column(name = "affectedProjects")
    })
    List<AdvisoriesPortfolioRow> getAllAdvisories();


    record ProjectAdvisoryFinding(
            String name,
            float confidence,
            String desc,
            String group,
            String version,
            String componentUuid,
            long totalCount
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOrderByClause" type="String" -->
            <#-- @ftlvariable name="apiFilterParameter" type="String" -->
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT "COMPONENT"."NAME" AS "name"
               , "MATCHING_PERCENTAGE" AS "confidence"
               , "DESCRIPTION" AS "desc"
               , "GROUP" AS "group"
               , "VERSION" AS "version"
               , "COMPONENT"."UUID" AS "componentUuid"
               , COUNT(*) OVER() AS "totalCount"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "COMPONENT" ON "FINDINGATTRIBUTION"."COMPONENT_ID" = "COMPONENT"."ID"
            INNER JOIN "CSAFMAPPING"
              ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            WHERE "FINDINGATTRIBUTION"."PROJECT_ID" = :projectId
            AND "CSAFDOCUMENT_ID" = :advisoryId
            <#if apiFilterParameter??>
                AND (
                    LOWER("COMPONENT"."NAME") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
                    OR LOWER("COMPONENT"."VERSION") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
                    OR LOWER("COMPONENT"."GROUP") LIKE ('%' || LOWER(${apiFilterParameter}) || '%')
                )
            </#if>
            
            <#if apiOrderByClause??>
                ${apiOrderByClause}
            <#else>
                ORDER BY "name" ASC
            </#if>
            ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.ProjectAdvisoryFinding.class)
    @AllowApiOrdering(by = {
            @AllowApiOrdering.Column(name = "name"),
            @AllowApiOrdering.Column(name = "version"),
            @AllowApiOrdering.Column(name = "group"),
            @AllowApiOrdering.Column(name = "confidence")
    })
    List<AdvisoryDao.ProjectAdvisoryFinding> getFindingsByProjectAdvisory(@Bind long projectId, @Bind long advisoryId);

}