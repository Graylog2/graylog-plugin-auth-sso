package org.graylog.plugins.auth.httpheaders;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.database.ValidationException;
import org.graylog2.plugin.database.users.User;
import org.graylog2.shared.security.HttpHeadersToken;
import org.graylog2.shared.security.ShiroSecurityContext;
import org.graylog2.shared.users.UserService;
import org.graylog2.users.RoleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.ws.rs.core.MultivaluedMap;
import java.util.Collections;
import java.util.Optional;

public class HttpHeadersAuth extends AuthenticatingRealm {
    private static final Logger LOG = LoggerFactory.getLogger(HttpHeadersAuth.class);

    public static final String NAME = "trusted-headers";

    private final UserService userService;
    private final ClusterConfigService clusterConfigService;
    private final RoleService roleService;

    @Inject
    public HttpHeadersAuth(UserService userService,
                           ClusterConfigService clusterConfigService,
                           RoleService roleService) {
        this.userService = userService;
        this.clusterConfigService = clusterConfigService;
        this.roleService = roleService;
        setAuthenticationTokenClass(HttpHeadersToken.class);
        setCredentialsMatcher(new AllowAllCredentialsMatcher());
        setCachingEnabled(false);
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        HttpHeadersToken headersToken = (HttpHeadersToken) token;
        final MultivaluedMap<String, String> requestHeaders = headersToken.getHeaders();

        final TrustedHeaderAuthenticatorConfig config = clusterConfigService.getOrDefault(
                TrustedHeaderAuthenticatorConfig.class,
                TrustedHeaderAuthenticatorConfig.defaultConfig());

        final String usernameHeader = config.usernameHeader();

        final Optional<String> userNameOption = headerValue(requestHeaders, usernameHeader);
        if (userNameOption.isPresent()) {
            final String username = userNameOption.get();
            User user = userService.load(username);
            if (user == null) {
                if (config.autoCreateUser()) {
                    user = userService.create();

                    // common fields
                    user.setName(username);
                    user.setExternal(true);
                    user.setPassword("dummy password");
                    user.setPermissions(Collections.emptyList());

                    // fields based on optional headers
                    final Optional<String> fullnameHeaderOption = headerValue(requestHeaders, config.fullnameHeader());
                    if (fullnameHeaderOption.isPresent()) {
                        user.setFullName(fullnameHeaderOption.get());
                    } else {
                        user.setFullName(username);
                    }

                    final Optional<String> emailHeaderOption = headerValue(requestHeaders, config.emailHeader());
                    if (emailHeaderOption.isPresent()) {
                        user.setEmail(emailHeaderOption.get());
                    } else {
                        user.setEmail(username + "@localhost");
                    }

                    // TODO we currently only support "Reader" and "Admin" here
                    final String defaultGroup = config.defaultGroup();
                    if (defaultGroup != null) {
                        if (defaultGroup.equalsIgnoreCase("admin")) {
                            user.setRoleIds(Collections.singleton(roleService.getAdminRoleObjectId()));
                        } else {
                            user.setRoleIds(Collections.singleton(roleService.getReaderRoleObjectId()));
                        }
                    } else {
                        user.setRoleIds(Collections.singleton(roleService.getReaderRoleObjectId()));
                    }
                    try {
                        userService.save(user);
                    } catch (ValidationException e) {
                        LOG.error("Unable to save auto created user {}. Not logging in with http header.", user, e);
                        return null;
                    }
                } else {
                    LOG.trace(
                            "No user named {} found and automatic user creation is disabled, not using content of trusted header {}",
                            username,
                            usernameHeader);
                    return null;
                }
            }
            LOG.trace("Trusted header {} set, continuing with user name {}", usernameHeader, user.getName());

            ShiroSecurityContext.requestSessionCreation(true);
            return new SimpleAccount(user.getName(), null, NAME);
        }
        return null;
    }

    private Optional<String> headerValue(MultivaluedMap<String, String> headers, @Nullable String headerName) {
        if (headerName == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(headers.getFirst(headerName.toLowerCase()));
    }

}
