package org.graylog.plugins.auth.httpheaders;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.graylog2.shared.security.SessionIdToken;
import org.graylog2.shared.security.ShiroSecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.MultivaluedHashMap;

public class HttpHeadersAuth extends AuthenticatingRealm {
    private static final Logger log = LoggerFactory.getLogger(HttpHeadersAuth.class);

    public static final String NAME = "trusted-headers";

    public HttpHeadersAuth() {
        setAuthenticationTokenClass(SessionIdToken.class);
        setCredentialsMatcher(new AllowAllCredentialsMatcher());
        setCachingEnabled(false);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        SessionIdToken sessionIdToken = (SessionIdToken) token;

        // only process external headers if we don't currently have an established session
        if (!"undefined".equals(sessionIdToken.getSessionId())) {
            log.trace("Skipping trusted HTTP headers check because we have an active session {}", sessionIdToken.getSessionId());
            return null;
        }

        final MultivaluedHashMap<String, String> requestHeaders = ShiroSecurityContext.requestHeaders();
        log.info("Looking at headers {}", requestHeaders);
        if (requestHeaders.containsKey("remote-user")) {
            // TODO refactor user creation

            final String userName = requestHeaders.getFirst("remote-user");
            log.info("Trusted header {} set, continuing with user name {}", "Remote-User", userName);
            return new SimpleAccount(userName, null, "trusted-header");
        }
        return null;
    }
}
