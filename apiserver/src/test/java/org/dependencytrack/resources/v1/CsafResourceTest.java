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
import alpine.server.filters.AuthenticationFilter;
import jakarta.json.JsonArray;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.CsafSourceEntity;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

public class CsafResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(CsafResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class));

    @Before
    @Override
    public void before() throws Exception {
        super.before();

    }

    @Test
    public void createCsafSourceTest() throws Exception {
        CsafSourceEntity aggregator = new CsafSourceEntity();
        aggregator.setName("Testsource");
        aggregator.setUrl("example.com");
        aggregator.setEnabled(true);

        Response response = jersey.target(V1_CSAF).path("/aggregators/").request().header(X_API_KEY, apiKey)
                .put(Entity.entity(aggregator, MediaType.APPLICATION_JSON));
        Assert.assertEquals(Response.Status.CREATED.getStatusCode(), response.getStatus());

        response = jersey.target(V1_CSAF).path("/aggregators/").request().header(X_API_KEY, apiKey).get(Response.class);
        Assert.assertEquals(Response.Status.OK.getStatusCode(), response.getStatus(), 0);

        JsonArray json = parseJsonArray(response);
        Assert.assertNotNull(json);
    }
}
