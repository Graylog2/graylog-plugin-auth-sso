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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.database.users.User;
import org.graylog2.security.realm.LdapUserAuthenticator;
import org.graylog2.shared.users.UserService;
import org.graylog2.users.RoleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.graylog.plugins.auth.sso.HeaderRoleUtil.*;

/**
 * Checking the session if it still matches the user and the roles in the HTTP request SSO headers.
 * This is necessary as {@link SsoAuthRealm} is only called at the creation of the session.
 * <p>
 * DESIGN DECISIONS
 * <p>
 * #1 This class doesn't honor the additional trust proxies. This leads to closing more session than necessary,
 * but avoids duplicating the logic here with the danger of failing to call it identically.
 * <p>
 * #2 If role syncing with Graylog is activated, the first request of a session checks roles against the user database.
 * If this matches, the contents of the role header are cached in the session and checked again if the role headers of a request change.
 * If this doesn't match, the user is logged out and the session is terminated. In a SSO system this will trigger a re-login
 * and a re-sync of the user roles.
 *
 */
/* This needs to have a lower priority than the {@link org.graylog2.shared.security.ShiroAuthenticationFilter}
 * so that the {@link Subject} is already populated. */
@Priority(Priorities.AUTHENTICATION + 1)
public class SsoAuthenticationFilter implements ContainerRequestFilter {
    private static final Logger LOG = LoggerFactory.getLogger(SsoAuthenticationFilter.class);
    private static final String VERIFIED_ROLES = SsoAuthenticationFilter.class.getName() + ".VERIFIED_USERS";

    private final ClusterConfigService clusterConfigService;
    private final RoleService roleService;
    private final UserService userService;
    private final LdapUserAuthenticator ldapAuthenticator;

    @Inject
    public SsoAuthenticationFilter(ClusterConfigService clusterConfigService, RoleService roleService, UserService userService, LdapUserAuthenticator ldapAuthenticator) {
        this.clusterConfigService = clusterConfigService;
        this.roleService = roleService;
        this.userService = userService;
        this.ldapAuthenticator = ldapAuthenticator;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) {

        final SsoAuthConfig config = clusterConfigService.getOrDefault(
                SsoAuthConfig.class,
                SsoAuthConfig.defaultConfig(""));

        Subject subject = SecurityUtils.getSubject();
        // the subject needs to be inspected only if there is a session.
        // If there is no session, Shiro has checked the headers on this request already
        if (subject.getSession(false) != null) {
            Session session = subject.getSession();
            final String usernameHeader = config.usernameHeader();
            final Optional<String> userNameOption = headerValue(containerRequestContext.getHeaders(), usernameHeader);
            // is the header with the user name is present ...
            if (userNameOption.isPresent()) {
                String username = userNameOption.get();
                if (!username.equals(subject.getPrincipal())) {
                    // terminate the session and return "unauthorized" for this request
                    LOG.warn("terminating session of {} as new user {} appears in the header", subject.getPrincipal(), username);
                    subject.logout();
                    throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());
                }
                if (config.syncRoles()) {
                    Optional<List<String>> rolesList = headerValues(containerRequestContext.getHeaders(), config.rolesHeader());
                    if (rolesList.isPresent() && !rolesList.get().equals(session.getAttribute(VERIFIED_ROLES))) {
                        User user = null;
                        if (ldapAuthenticator.isEnabled()) {
                            user = ldapAuthenticator.syncLdapUser(username);
                        }
                        if (user == null) {
                            user = userService.load(username);
                        }
                        if (user == null) {
                            LOG.error("user {} not found",
                                    subject.getPrincipal());
                            subject.logout();
                            throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());
                        }
                        Set<String> roleNames = csv(rolesList.get());
                        Set<String> existingRoles = user.getRoleIds();

                        Set<String> roleIds = getRoleIds(roleService, roleNames);
                        if (!existingRoles.equals(roleIds)) {
                            // terminate the session and return "unauthorized" for this request
                            LOG.warn("terminating session of user {} as roles in user differ from roles in header ({})",
                                    subject.getPrincipal(),
                                    roleNames);
                            subject.logout();
                            throw new NotAuthorizedException(Response.status(Response.Status.UNAUTHORIZED).build());
                        }
                        session.setAttribute(VERIFIED_ROLES, rolesList.get());
                    }
                }
            }
        }
    }

}
