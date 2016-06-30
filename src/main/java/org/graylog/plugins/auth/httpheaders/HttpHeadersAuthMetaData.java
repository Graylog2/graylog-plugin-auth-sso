package org.graylog.plugins.auth.httpheaders;

import org.graylog2.plugin.PluginMetaData;
import org.graylog2.plugin.ServerStatus;
import org.graylog2.plugin.Version;

import java.net.URI;
import java.util.Collections;
import java.util.Set;

/**
 * Implement the PluginMetaData interface here.
 */
public class HttpHeadersAuthMetaData implements PluginMetaData {
    @Override
    public String getUniqueId() {
        return "org.graylog.plugins.auth.httpheaders.HttpHeadersAuthPlugin";
    }

    @Override
    public String getName() {
        return "Trusted HTTP Headers Authentication Provider";
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
        return "Authentication provider based on trusted HTTP headers (SSO)";
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
