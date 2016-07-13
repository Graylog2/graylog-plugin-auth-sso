package org.graylog.plugins.auth.sso;

import com.google.inject.Scopes;
import org.graylog2.plugin.PluginModule;

/**
 * Extend the PluginModule abstract class here to add you plugin to the system.
 */
public class SsoAuthModule extends PluginModule {

    @Override
    protected void configure() {
        authenticationRealmBinder().addBinding(SsoAuthRealm.NAME).to(SsoAuthRealm.class).in(Scopes.SINGLETON);
        addRestResource(SsoConfigResource.class);
        addPermissions(SsoAuthPermissions.class);
    }
}
