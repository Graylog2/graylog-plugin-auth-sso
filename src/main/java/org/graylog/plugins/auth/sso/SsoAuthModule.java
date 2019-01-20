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

import com.google.inject.Scopes;
import com.google.inject.multibindings.Multibinder;
import org.graylog.plugins.auth.sso.audit.SsoAuthAuditEventTypes;
import org.graylog2.plugin.PluginModule;

import javax.ws.rs.container.DynamicFeature;

/**
 * Extend the PluginModule abstract class here to add you plugin to the system.
 */
public class SsoAuthModule extends PluginModule {

    @Override
    protected void configure() {
        authenticationRealmBinder().addBinding(SsoAuthRealm.NAME).to(SsoAuthRealm.class).in(Scopes.SINGLETON);
        addRestResource(SsoConfigResource.class);
        addPermissions(SsoAuthPermissions.class);
        addAuditEventTypes(SsoAuthAuditEventTypes.class);

        Multibinder<Class<? extends DynamicFeature>> setBinder = jerseyDynamicFeatureBinder();
        setBinder.addBinding().toInstance(SsoSecurityBinding.class);
    }
}
