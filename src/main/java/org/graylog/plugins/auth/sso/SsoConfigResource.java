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

import com.google.common.base.Joiner;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.graylog.plugins.auth.sso.audit.SsoAuthAuditEventTypes;
import org.graylog2.audit.jersey.AuditEvent;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.rest.PluginRestResource;
import org.graylog2.shared.rest.resources.RestResource;
import org.graylog2.utilities.IpSubnet;

import javax.inject.Inject;
import javax.inject.Named;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Set;

@Api(value = "SSO/Config", description = "Manage SSO authenticator configuration")
@Path("/config")
@Produces(MediaType.APPLICATION_JSON)
@RequiresAuthentication
public class SsoConfigResource extends RestResource implements PluginRestResource {

    private final ClusterConfigService clusterConfigService;
    private final String trustedProxies;

    @Inject
    private SsoConfigResource(ClusterConfigService clusterConfigService,
                              @Named("trusted_proxies") Set<IpSubnet> trustedProxies) {
        this.clusterConfigService = clusterConfigService;
        this.trustedProxies = Joiner.on(", ").join(trustedProxies);
    }

    @ApiOperation(value = "Get SSO configuration")
    @GET
    @RequiresPermissions(SsoAuthPermissions.CONFIG_READ)
    public SsoAuthConfig get() {
        final SsoAuthConfig config = clusterConfigService.getOrDefault(SsoAuthConfig.class,
                                                                       SsoAuthConfig.defaultConfig(trustedProxies));
        return config.toBuilder().trustedProxies(trustedProxies).build();
    }

    @ApiOperation(value = "Update SSO configuration")
    @Consumes(MediaType.APPLICATION_JSON)
    @PUT
    @RequiresPermissions(SsoAuthPermissions.CONFIG_UPDATE)
    @AuditEvent(type = SsoAuthAuditEventTypes.CONFIG_UPDATE)
    public SsoAuthConfig update(@ApiParam(name = "config", required = true) @NotNull SsoAuthConfig config) {
        // we do not want to store trustedProxies in the cluster config because it is not editable in the UI
        final SsoAuthConfig cleanConfig = config.toBuilder().trustedProxies(null).build();
        clusterConfigService.write(cleanConfig);
        // return the original one because the UI needs to see the trustedProxies again. Well, this time I _am_ sorry.
        return config;
    }

}
