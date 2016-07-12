package org.graylog.plugins.auth.httpheaders;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.graylog2.plugin.database.users.User;
import org.graylog2.shared.security.HttpHeadersToken;
import org.graylog2.shared.security.ShiroSecurityContext;
import org.graylog2.shared.users.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.core.MultivaluedMap;

public class HttpHeadersAuth extends AuthenticatingRealm {
    private static final Logger LOG = LoggerFactory.getLogger(HttpHeadersAuth.class);
    private static final String DEFAULT_HEADER = "Remote-User";

    public static final String NAME = "trusted-headers";

    private final UserService userService;

    @Inject
    public HttpHeadersAuth(UserService userService) {
        this.userService = userService;
        setAuthenticationTokenClass(HttpHeadersToken.class);
        setCredentialsMatcher(new AllowAllCredentialsMatcher());
        setCachingEnabled(false);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        HttpHeadersToken headersToken = (HttpHeadersToken) token;
        final MultivaluedMap<String, String> requestHeaders = headersToken.getHeaders();

        if (requestHeaders.containsKey(DEFAULT_HEADER.toLowerCase())) {
            final String userName = requestHeaders.getFirst(DEFAULT_HEADER.toLowerCase());
            final User user = userService.load(String.valueOf(userName));
            if (user == null) {
                LOG.trace("No user named {} found, not using content of trusted header {}", userName, DEFAULT_HEADER);
                return null;
            }

            LOG.trace("Trusted header {} set, continuing with user name {}", DEFAULT_HEADER, user.getName());

            ShiroSecurityContext.requestSessionCreation(true);
            return new SimpleAccount(user.getName(), null, NAME);
        }
        return null;
    }
}
