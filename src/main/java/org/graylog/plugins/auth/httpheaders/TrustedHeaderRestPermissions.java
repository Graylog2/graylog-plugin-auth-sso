package org.graylog.plugins.auth.httpheaders;

import com.google.common.collect.ImmutableSet;
import org.graylog2.plugin.security.Permission;
import org.graylog2.plugin.security.PluginPermissions;

import java.util.Collections;
import java.util.Set;

import static org.graylog2.plugin.security.Permission.create;

public class TrustedHeaderRestPermissions implements PluginPermissions {

    public static final String CONFIG_READ = "trustedheaderauthconfig:read";
    public static final String CONFIG_UPDATE = "trustedheaderauthconfig:edit";

    private final ImmutableSet<Permission> permissions = ImmutableSet.of(
            create(CONFIG_READ, "Read trusted HTTP header authenticator config"),
            create(CONFIG_UPDATE, "Update trusted HTTP header authenticator config")
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
