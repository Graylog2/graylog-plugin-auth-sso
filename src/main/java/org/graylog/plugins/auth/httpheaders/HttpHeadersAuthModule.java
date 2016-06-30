package org.graylog.plugins.auth.httpheaders;

import com.google.inject.Scopes;
import org.graylog2.plugin.PluginModule;

/**
 * Extend the PluginModule abstract class here to add you plugin to the system.
 */
public class HttpHeadersAuthModule extends PluginModule {

    @Override
    protected void configure() {
        authenticationRealmBinder().addBinding(HttpHeadersAuth.NAME).to(HttpHeadersAuth.class).in(Scopes.SINGLETON);
    }
}
