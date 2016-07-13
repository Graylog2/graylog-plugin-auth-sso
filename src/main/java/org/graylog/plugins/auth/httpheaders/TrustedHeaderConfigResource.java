package org.graylog.plugins.auth.httpheaders;

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

@Api(value = "AuthHttpHeaders/Config", description = "Manage trusted HTTP headers authenticator configuration")
@Path("/config")
@Produces(MediaType.APPLICATION_JSON)
@RequiresAuthentication
public class TrustedHeaderConfigResource extends RestResource implements PluginRestResource {

    private final ClusterConfigService clusterConfigService;

    @Inject
    private TrustedHeaderConfigResource(ClusterConfigService clusterConfigService) {
        this.clusterConfigService = clusterConfigService;
    }

    @ApiOperation(value = "Get authenticator configuration")
    @GET
    @RequiresPermissions(TrustedHeaderRestPermissions.CONFIG_READ)
    public TrustedHeaderAuthenticatorConfig get() {
        return clusterConfigService.getOrDefault(TrustedHeaderAuthenticatorConfig.class,
                                                 TrustedHeaderAuthenticatorConfig.defaultConfig());
    }

    @ApiOperation(value = "Update authenticator configuration")
    @Consumes(MediaType.APPLICATION_JSON)
    @PUT
    @RequiresPermissions(TrustedHeaderRestPermissions.CONFIG_UPDATE)
    public TrustedHeaderAuthenticatorConfig update(@ApiParam(name = "config", required = true) @NotNull TrustedHeaderAuthenticatorConfig config) {
        clusterConfigService.write(config);
        return config;
    }

}
