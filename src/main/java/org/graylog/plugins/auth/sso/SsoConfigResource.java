/**
 * This file is part of Graylog Archive.
 *
 * Graylog Archive is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog Archive is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog Archive.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.plugins.auth.sso;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.rest.PluginRestResource;
import org.graylog2.shared.rest.resources.RestResource;

import javax.inject.Inject;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

@Api(value = "SSO/Config", description = "Manage SSO authenticator configuration")
@Path("/config")
@Produces(MediaType.APPLICATION_JSON)
@RequiresAuthentication
public class SsoConfigResource extends RestResource implements PluginRestResource {

    private final ClusterConfigService clusterConfigService;

    @Inject
    private SsoConfigResource(ClusterConfigService clusterConfigService) {
        this.clusterConfigService = clusterConfigService;
    }

    @ApiOperation(value = "Get SSO configuration")
    @GET
    @RequiresPermissions(SsoAuthPermissions.CONFIG_READ)
    public SsoAuthConfig get() {
        return clusterConfigService.getOrDefault(SsoAuthConfig.class,
                                                 SsoAuthConfig.defaultConfig());
    }

    @ApiOperation(value = "Update SSO configuration")
    @Consumes(MediaType.APPLICATION_JSON)
    @PUT
    @RequiresPermissions(SsoAuthPermissions.CONFIG_UPDATE)
    public SsoAuthConfig update(@ApiParam(name = "config", required = true) @NotNull SsoAuthConfig config) {
        clusterConfigService.write(config);
        return config;
    }

}
