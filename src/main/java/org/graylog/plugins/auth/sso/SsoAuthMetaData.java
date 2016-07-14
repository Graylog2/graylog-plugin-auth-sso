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

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

/**
 * Implement the PluginMetaData interface here.
 */
public class SsoAuthMetaData implements PluginMetaData {
    @Override
    public String getUniqueId() {
        return "org.graylog.plugins.auth.sso.SsoAuthPlugin";
    }

    @Override
    public String getName() {
        return "Single Sign-On (SSO) Authentication Provider";
    }

    @Override
    public String getAuthor() {
        return "Graylog, Inc";
    }

    @Override
    public URI getURL() {
        return URI.create("https://www.graylog.org/");
    }

    @Override
    public Version getVersion() {
        return Version.from(1, 0, 0);
    }

    @Override
    public String getDescription() {
        return "SSO Authentication provider";
    }

    @Override
    public Version getRequiredVersion() {
        return Version.from(2, 1, 0, "SNAPSHOT");
    }

    @Override
    public Set<ServerStatus.Capability> getRequiredCapabilities() {
        return Collections.emptySet();
    }
}
