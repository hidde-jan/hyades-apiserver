package org.dependencytrack.persistence.jdbi;

import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;

import java.util.List;

public interface AdvisoryDao {

    record AdvisoryRow(
            String name,
            String url,
            int documentId,
            int findingsPerDoc
    ) {
    }

    @SqlQuery(/* language=InjectedFreeMarker */ """
            <#-- @ftlvariable name="apiOffsetLimitClause" type="String" -->
            
            SELECT "NAME" AS "name"
                 , "URL" AS "url"
                 , "CSAFDOCUMENT_ID" AS "documentId"
                 , COUNT("FINDINGATTRIBUTION"."ID") AS "findingsPerDoc"
            FROM "FINDINGATTRIBUTION"
            INNER JOIN "CSAFMAPPING"
               ON "FINDINGATTRIBUTION"."VULNERABILITY_ID" = "CSAFMAPPING"."VULNERABILITY_ID"
            INNER JOIN "CSAFDOCUMENTENTITY" ON "CSAFMAPPING"."CSAFDOCUMENT_ID" = "CSAFDOCUMENTENTITY"."ID"
            WHERE "PROJECT_ID" = :projectId
            GROUP BY "CSAFDOCUMENT_ID", "NAME", "URL"
            
             ${apiOffsetLimitClause!}
            """)
    @RegisterConstructorMapper(AdvisoryDao.AdvisoryRow.class)
    List<AdvisoryDao.AdvisoryRow> getAdvisoriesByProject(@Bind long projectId, @Bind boolean includeSuppressed);

}
