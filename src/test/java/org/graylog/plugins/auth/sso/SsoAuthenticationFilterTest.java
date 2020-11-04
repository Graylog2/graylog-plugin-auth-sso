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
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.glassfish.jersey.message.internal.MediaTypeProvider;
import org.glassfish.jersey.message.internal.OutboundJaxrsResponse;
import org.glassfish.jersey.message.internal.OutboundMessageContext;
import org.graylog2.database.NotFoundException;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.database.users.User;
import org.graylog2.security.realm.LdapUserAuthenticator;
import org.graylog2.shared.users.Role;
import org.graylog2.shared.users.UserService;
import org.graylog2.users.RoleService;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.RuntimeDelegate;
import java.util.*;

import static org.mockito.Mockito.*;

public class SsoAuthenticationFilterTest {

    private static final String USER_HEADER = "Remote-User";
    private static final String ROLE_HEADER = "Roles";

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    private SsoAuthConfig config = SsoAuthConfig.builder()
            .usernameHeader(USER_HEADER)
            .autoCreateUser(false)
            .requireTrustedProxies(false)
            .syncRoles(true)
            .rolesHeader(ROLE_HEADER)
            .autoBuild();

    private SsoAuthenticationFilter filter;
    private Subject subject;
    private MultivaluedMap<String, String> headers;
    private ContainerRequestContext containerRequest;
    private UserService userService;
    private RoleService roleService;

    @Before
    public void setup() {
        // ClusterConfigService
        ClusterConfigService clusterConfigService = mock(ClusterConfigService.class);
        when(clusterConfigService.getOrDefault(
                SsoAuthConfig.class,
                SsoAuthConfig.defaultConfig(""))).thenReturn(config);

        // RoleService
        roleService = mock(RoleService.class);

        // UserService
        userService = mock(UserService.class);

        // LdapUserAuthenticator
        LdapUserAuthenticator ldapAuthenticator = mock(LdapUserAuthenticator.class);

        // SsoAuthenticationFilter = System under Test
        filter = new SsoAuthenticationFilter(clusterConfigService, roleService, userService, ldapAuthenticator);

        // SecurityManager
        SecurityManager securityManager = mock(SecurityManager.class);
        SecurityUtils.setSecurityManager(securityManager);

        // Subject
        subject = mock(Subject.class);
        when(securityManager.createSubject(any())).thenReturn(subject);

        // Session
        Session session = mock(Session.class);
        when(subject.getSession(anyBoolean())).thenReturn(session);
        when(subject.getSession()).thenReturn(session);
        Map<Object, Object> attributes = new HashMap<>();
        doAnswer(invocation -> {
            attributes.put(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(session).setAttribute(any(), any());
        doAnswer(invocation -> attributes.get(invocation.getArgument(0))).when(session).getAttribute(any());

        // ContainerRequestContext
        containerRequest = mock(ContainerRequestContext.class);
        headers = new MultivaluedHashMap<>();
        when(containerRequest.getHeaders()).thenReturn(headers);

        // RuntimeDelegate
        RuntimeDelegate runtimeDelegate = mock(RuntimeDelegate.class);
        RuntimeDelegate.setInstance(runtimeDelegate);
        when(runtimeDelegate.createHeaderDelegate(MediaType.class)).thenReturn(new MediaTypeProvider());
        when(runtimeDelegate.createResponseBuilder())
                .thenAnswer(invocation -> new OutboundJaxrsResponse.Builder(new OutboundMessageContext()));
    }

    @After
    public void cleanup() {
        RuntimeDelegate.setInstance(null);
        SecurityUtils.setSecurityManager(null);
    }


    @Test
    public void shouldAcceptWhenSubjectNameIsMatches() {
        // given...
        headers.put(USER_HEADER.toLowerCase(), Collections.singletonList("horst"));
        when(subject.getPrincipal()).thenReturn("horst");
        User user = mock(User.class);
        when(userService.load(matches("horst"))).thenReturn(user);

        // when...
        filter.filter(containerRequest);

        // then ...
        // ... succeeds
    }

    @Test
    public void shouldDenyWhenSubjectNameDoesntMatch() {
        headers.put(USER_HEADER.toLowerCase(), Collections.singletonList("horst"));
        when(subject.getPrincipal()).thenReturn("nothorst");

        // expecting...
        exceptionRule.expect(NotAuthorizedException.class);

        // when...
        filter.filter(containerRequest);
    }

    @Test
    public void shouldAcceptWhenRolesMatch() throws NotFoundException {
        // given...
        headers.put(USER_HEADER.toLowerCase(), Collections.singletonList("horst"));
        List<String> roles = Arrays.asList("role1", "role2");
        headers.put(ROLE_HEADER.toLowerCase(), Collections.singletonList(String.join(",", roles)));
        when(subject.getPrincipal()).thenReturn("horst");
        User user = mock(User.class);
        when(userService.load(matches("horst"))).thenReturn(user);
        mockRoles(roles, user);

        // when...
        filter.filter(containerRequest);
        // ... call a second time to see if caching of headers
        filter.filter(containerRequest);

        // then ...
        verify(userService, times(1)).load("horst");
    }

    @Test
    public void shouldDenyWhenRolesNameDontMatch() throws NotFoundException {
        // given...
        headers.put(USER_HEADER.toLowerCase(), Collections.singletonList("horst"));
        List<String> roles = Arrays.asList("role1", "role2");
        headers.put(ROLE_HEADER.toLowerCase(), Collections.singletonList(String.join(",", roles.subList(0, 1))));
        when(subject.getPrincipal()).thenReturn("horst");
        User user = mock(User.class);
        when(userService.load(matches("horst"))).thenReturn(user);
        mockRoles(roles, user);

        // expecting...
        exceptionRule.expect(NotAuthorizedException.class);

        // when...
        filter.filter(containerRequest);
    }

    private void mockRoles(List<String> roles, User user) throws NotFoundException {
        Set<String> roleIds = new HashSet<>();
        when(user.getRoleIds()).thenReturn(roleIds);
        for (String role : roles) {
            String roleId = "idof_" + role;
            roleIds.add(roleId);
            when(roleService.exists(role)).thenReturn(true);
            when(roleService.load(role)).thenAnswer(invocation -> {
                Role r = mock(Role.class);
                when(r.getId()).thenReturn(roleId);
                return r;
            });
        }
    }

}