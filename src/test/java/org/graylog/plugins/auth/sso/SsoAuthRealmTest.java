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

import com.google.common.collect.Maps;
import org.apache.shiro.authc.AuthenticationInfo;
import org.glassfish.jersey.internal.util.collection.MultivaluedStringMap;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.security.PasswordAlgorithmFactory;
import org.graylog2.security.hashing.SHA1HashPasswordAlgorithm;
import org.graylog2.shared.security.HttpHeadersToken;
import org.graylog2.shared.security.Permissions;
import org.graylog2.shared.users.UserService;
import org.graylog2.users.RoleService;
import org.graylog2.users.UserImpl;
import org.graylog2.utilities.IpSubnet;
import org.junit.Test;

import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SsoAuthRealmTest {

    @Test
    public void checkSubnetConfig() throws UnknownHostException {
        Set<IpSubnet> trustedProxies = Collections.singleton(new IpSubnet("192.168.0.0/24"));
        final ClusterConfigService configService = mock(ClusterConfigService.class);

        when(configService.getOrDefault(any(), any()))
                .thenReturn(SsoAuthConfig.builder()
                                    .usernameHeader("X-Remote-User")
                                    .autoCreateUser(false)
                                    .emailHeader("")
                                    .fullnameHeader("")
                                    .requireTrustedProxies(false)
                                    .build());

        final UserService userService = mock(UserService.class);
        when(userService.load(eq("horst"))).thenReturn(new UserImpl(mock(PasswordAlgorithmFactory.class),
                                                                    mock(Permissions.class),
                                                                    Maps.newHashMap()));
        final SsoAuthRealm realm = new SsoAuthRealm(userService,
                                                    configService,
                                                    mock(RoleService.class),
                                                    trustedProxies);

        final MultivaluedStringMap headers = new MultivaluedStringMap();
        // headers must be lowercase, jersey does this the same way
        headers.put("x-remote-user", Collections.singletonList("horst"));
        final HttpHeadersToken headersToken = new HttpHeadersToken(headers, "192.168.0.1", "192.168.0.1");
        final SsoAuthRealm realmSpy = spy(realm);
        final AuthenticationInfo info = realmSpy.doGetAuthenticationInfo(headersToken);

        assertThat(info).isNotNull();
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isNotNull();

        verify(userService).load(eq("horst"));
        verify(realmSpy, never()).inTrustedSubnets(anyString());
    }

    @Test
    public void testDefaultDomain() {

        final ClusterConfigService configService = mock(ClusterConfigService.class);

        when(configService.getOrDefault(any(), any()))
                .thenReturn(SsoAuthConfig.builder()
                                    .usernameHeader("X-Remote-User")
                                    .autoCreateUser(true)
                                    .emailHeader(null)
                                    .fullnameHeader(null)
                                    .requireTrustedProxies(false)
                                    .defaultEmailDomain("domain.de")
                                    .build());

        final UserService userService = mock(UserService.class);
        final UserImpl user = new UserImpl(
                new PasswordAlgorithmFactory(Collections.emptyMap(),
                                             new SHA1HashPasswordAlgorithm("1234567890")),
                mock(Permissions.class),
                Maps.newHashMap());
        when(userService.create()).thenReturn(user);

        final RoleService roleService = mock(RoleService.class);
        when(roleService.getReaderRoleObjectId()).thenReturn("57a1d276227c473674e1d997");
        final SsoAuthRealm realm = new SsoAuthRealm(userService,
                                                    configService,
                                                    roleService,
                                                    Collections.emptySet());

        final MultivaluedStringMap headers = new MultivaluedStringMap();
        // headers must be lowercase, jersey does this the same way
        headers.put("x-remote-user", Collections.singletonList("horst"));
        final HttpHeadersToken headersToken = new HttpHeadersToken(headers, "192.168.0.1", "192.168.0.1");
        final SsoAuthRealm realmSpy = spy(realm);
        final AuthenticationInfo info = realmSpy.doGetAuthenticationInfo(headersToken);

        assertThat(info).isNotNull();
        verify(userService).create();
        assertThat(user.getEmail()).isEqualTo("horst@domain.de");
    }

    @Test
    public void testDefaultDomainNotSet() {

        final ClusterConfigService configService = mock(ClusterConfigService.class);

        when(configService.getOrDefault(any(), any()))
                .thenReturn(SsoAuthConfig.builder()
                                    .usernameHeader("X-Remote-User")
                                    .autoCreateUser(true)
                                    .emailHeader(null)
                                    .fullnameHeader(null)
                                    .requireTrustedProxies(false)
                                    .build());

        final UserService userService = mock(UserService.class);
        final UserImpl user = new UserImpl(
                new PasswordAlgorithmFactory(Collections.emptyMap(),
                                             new SHA1HashPasswordAlgorithm("1234567890")),
                mock(Permissions.class),
                Maps.newHashMap());
        when(userService.create()).thenReturn(user);

        final RoleService roleService = mock(RoleService.class);
        when(roleService.getReaderRoleObjectId()).thenReturn("57a1d276227c473674e1d997");
        final SsoAuthRealm realm = new SsoAuthRealm(userService,
                                                    configService,
                                                    roleService,
                                                    Collections.emptySet());

        final MultivaluedStringMap headers = new MultivaluedStringMap();
        // headers must be lowercase, jersey does this the same way
        headers.put("x-remote-user", Collections.singletonList("horst"));
        final HttpHeadersToken headersToken = new HttpHeadersToken(headers, "192.168.0.1", "192.168.0.1");
        final SsoAuthRealm realmSpy = spy(realm);
        final AuthenticationInfo info = realmSpy.doGetAuthenticationInfo(headersToken);

        assertThat(info).isNotNull();
        verify(userService).create();
        assertThat(user.getEmail()).isEqualTo("horst@localhost");
    }
}