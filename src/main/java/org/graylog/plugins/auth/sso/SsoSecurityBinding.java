/**
 * This file is part of Graylog.
 *
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.plugins.auth.sso;

import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.graylog2.shared.security.ShiroSecurityBinding;
import org.graylog2.shared.security.ShiroSecurityContextFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import java.lang.reflect.Method;

/**
 * Adding the {@link SsoAuthenticationFilter} to each resource that requires authentication.
 * This is mirroring the efforts in {@link ShiroSecurityBinding}
 */
public class SsoSecurityBinding implements DynamicFeature {
    private static final Logger LOG = LoggerFactory.getLogger(SsoSecurityBinding.class);

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        final Class<?> resourceClass = resourceInfo.getResourceClass();
        final Method resourceMethod = resourceInfo.getResourceMethod();

        context.register(ShiroSecurityContextFilter.class);

        if (resourceMethod.isAnnotationPresent(RequiresAuthentication.class) || resourceClass.isAnnotationPresent(RequiresAuthentication.class)) {
            if (resourceMethod.isAnnotationPresent(RequiresGuest.class)) {
                LOG.debug("Resource method {}#{} is marked as unauthenticated, skipping setting filter.", resourceClass.getCanonicalName(), resourceMethod.getName());
            } else {
                LOG.debug("Resource method {}#{} requires an authenticated user.", resourceClass.getCanonicalName(), resourceMethod.getName());
                context.register(SsoAuthenticationFilter.class);
            }
        }

    }
}
