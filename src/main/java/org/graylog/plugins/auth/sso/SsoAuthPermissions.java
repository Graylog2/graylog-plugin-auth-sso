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

import com.google.common.collect.ImmutableSet;
import org.graylog2.plugin.security.Permission;
import org.graylog2.plugin.security.PluginPermissions;

import java.util.Collections;
import java.util.Set;

import static org.graylog2.plugin.security.Permission.create;

public class SsoAuthPermissions implements PluginPermissions {

    public static final String CONFIG_READ = "ssoauthconfig:read";
    public static final String CONFIG_UPDATE = "ssoauthconfig:edit";

    private final ImmutableSet<Permission> permissions = ImmutableSet.of(
            create(CONFIG_READ, "Read SSO authenticator config"),
            create(CONFIG_UPDATE, "Update SSO authenticator config")
    );

    @Override
    public Set<Permission> permissions() {
        return permissions;
    }

    @Override
    public Set<Permission> readerBasePermissions() {
        return Collections.emptySet();
    }
}
