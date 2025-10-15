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

import alpine.common.logging.Logger;
import alpine.persistence.PaginatedResult;
import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.CsafDocumentEntity;
import org.dependencytrack.model.CsafMapping;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.jdbi.AdvisoryDao;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.openapi.PaginatedApi;
import org.dependencytrack.resources.v1.problems.ProblemDetails;

import javax.jdo.JDOObjectNotFoundException;
import java.util.List;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.dependencytrack.resources.v1.FindingResource.MEDIA_TYPE_SARIF_JSON;

/**
 * JAX-RS resources for advisories.
 *
 * @author Lawrence Dean
 * @since TODO set version
 */
@Path("/v1/advisories")
@Tag(name = "advisories")
@SecurityRequirements({
        @SecurityRequirement(name = "ApiKeyAuth"),
        @SecurityRequirement(name = "BearerAuth")
})
public class AdvisoriesResource extends AbstractApiResource {
    private static final Logger LOGGER = Logger.getLogger(AdvisoriesResource.class);

    @GET
    @Produces({MediaType.APPLICATION_JSON, MEDIA_TYPE_SARIF_JSON})
    @Operation(
            summary = "Returns a list of all advisories",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>" // TODO discuss permission
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all advisories for a specific project, or a SARIF file",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of advisories", schema = @Schema(format = "integer")),
                    content = {
                            @Content(array = @ArraySchema(schema = @Schema(implementation = AdvisoryDao.AdvisoryRow.class)), mediaType = MediaType.APPLICATION_JSON),
                            @Content(schema = @Schema(type = "string"), mediaType = MEDIA_TYPE_SARIF_JSON)
                    }
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to advisories prohibited",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
    })
    @PaginatedApi
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAdvisories() {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final PaginatedResult result = qm.getAdvisories();
            return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
        }
    }

    @GET
    @Path("/{advisoryId}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(summary = "Returns the details of an Advisory", description = "<p>Requires permission <strong>VULNERABILITY_ANALYSIS_READ</strong></p>")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Details of given advisory"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @PermissionRequired(Permissions.Constants.VULNERABILITY_ANALYSIS_READ)
    public Response getAdvisoryById(@Parameter(description = "The advisoryId of the CSAF document to view", schema = @Schema(type = "integer"), required = true) @PathParam("advisoryId") long advisoryId) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final CsafDocumentEntity advisoryEntity = qm.getObjectById(CsafDocumentEntity.class, advisoryId);
            if (advisoryEntity == null) {
                return Response.status(Response.Status.NOT_FOUND).entity("The requested CSAF document could not be found.").build();
            }

            final List<AdvisoryDao.ProjectRow> affectedProjects = withJdbiHandle(getAlpineRequest(), handle ->
                    handle.attach(AdvisoryDao.class).getProjectsByAdvisory(advisoryEntity.getId()));

            final List<AdvisoryDao.VulnerabilityRow> vulnerabilities = withJdbiHandle(getAlpineRequest(), handle ->
                    handle.attach(AdvisoryDao.class).getVulnerabilitiesByAdvisory(advisoryEntity.getId()));

            final var result = new AdvisoryDao.AdvisoryResult(
                    advisoryEntity,
                    affectedProjects,
                    vulnerabilities
            );
            return Response.ok(result).build();
        } catch (JDOObjectNotFoundException e) {
            return Response.status(Response.Status.NOT_FOUND).entity("The requested CSAF document could not be found.").build();
        }
    }


    @GET
    @Path("/project/{uuid}")
    @Produces({MediaType.APPLICATION_JSON, MEDIA_TYPE_SARIF_JSON})
    @Operation(
            summary = "Returns a list of matched advisories on a given project",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all advisories for a specific project, or a SARIF file",
                    headers = @Header(name = TOTAL_COUNT_HEADER, description = "The total number of advisories", schema = @Schema(format = "integer")),
                    content = {
                            @Content(array = @ArraySchema(schema = @Schema(implementation = CsafMapping.class)), mediaType = MediaType.APPLICATION_JSON),
                            @Content(schema = @Schema(type = "string"), mediaType = MEDIA_TYPE_SARIF_JSON)
                    }
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project could not be found")
    })
    @PaginatedApi
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getAdvisoriesByProject(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
                                           @PathParam("uuid") @ValidUuid String uuid,
                                           @Parameter(description = "Optionally includes suppressed advisories")
                                           @QueryParam("suppressed") boolean suppressed,
                                           @Parameter(description = "Optionally limit advisories to specific sources of vulnerability intelligence")
                                           @QueryParam("source") Vulnerability.Source source,
                                           @HeaderParam("accept") String acceptHeader) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                requireAccess(qm, project);
                final PaginatedResult result = qm.getAdvisoriesByProject(project.getId(), suppressed);
                return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }

    @GET
    @Path("/project/{uuid}/advisory/{advisoryId}")
    @Produces({MediaType.APPLICATION_JSON})
    @Operation(
            summary = "Returns a list of findings associated to project x advisory",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "A list of all advisory findings for a specific project and advisory",
                    content = {
                            @Content(array = @ArraySchema(schema = @Schema(implementation = AdvisoryDao.ProjectAdvisoryFinding.class)), mediaType = MediaType.APPLICATION_JSON),
                    }
            ),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(
                    responseCode = "403",
                    description = "Access to the requested project is forbidden",
                    content = @Content(schema = @Schema(implementation = ProblemDetails.class), mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
            @ApiResponse(responseCode = "404", description = "The project or advisory could not be found")
    })
    @PaginatedApi
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response getFindingsByProjectAdvisory(@Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"), required = true)
                                                 @PathParam("uuid") @ValidUuid String uuid,
                                                 @Parameter(description = "The advisoryId", schema = @Schema(type = "string"), required = true)
                                                 @PathParam("advisoryId") long advisoryId,
                                                 @HeaderParam("accept") String acceptHeader) {
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            final Project project = qm.getObjectByUuid(Project.class, uuid);
            if (project != null) {
                requireAccess(qm, project);
                final PaginatedResult result = qm.getFindingsByProjectAdvisory(project.getId(), advisoryId);
                return Response.ok(result.getObjects()).header(TOTAL_COUNT_HEADER, result.getTotal()).build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).entity("The project could not be found.").build();
            }
        }
    }
}
