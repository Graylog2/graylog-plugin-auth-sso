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
