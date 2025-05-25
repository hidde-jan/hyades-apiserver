package org.dependencytrack.persistence.jdbi;

import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.List;

public interface AdvisoryDao {


    record AdvisoryRow(
            String name,
            int projectId,
            String url,
            int documentId,
            int findingsPerDoc
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT "NAME" AS "name"
                 , "PROJECT_ID" AS "projectId"
                 , "URL" AS "url"
                 , "CSAFDOCUMENT_ID" AS "documentId"
                 , COUNT("FINDINGATTRIBUTION"."ID") AS "findingsPerDoc"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "CSAFMAPPING"
               ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            WHERE "PROJECT_ID" = :projectId
            GROUP BY "CSAFDOCUMENT_ID", "NAME", "URL", "PROJECT_ID"
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.AdvisoryRow.class)
    List<AdvisoryDao.AdvisoryRow> getAdvisoriesByProject(@Bind long projectId, @Bind boolean includeSuppressed);


    record AdvisoriesPortfolioRow(
            String name,
            int affectedComponents,
            int affectedProjects,
            String url,
            int documentId
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT "NAME" AS "name"
                     , COUNT("PROJECT_ID") AS "affectedComponents"
                     , COUNT(DISTINCT "PROJECT_ID") AS "affectedProjects"
                     , "URL" AS "url"
                     , "CSAFDOCUMENT_ID" AS "documentId"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "CSAFMAPPING"
            ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            GROUP BY "CSAFDOCUMENT_ID","NAME","URL"
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.AdvisoriesPortfolioRow.class)
    List<AdvisoriesPortfolioRow> getAllAdvisories();

}
