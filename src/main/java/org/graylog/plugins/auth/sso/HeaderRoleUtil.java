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

import org.graylog2.database.NotFoundException;
import org.graylog2.shared.users.Role;
import org.graylog2.users.RoleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.validation.constraints.NotNull;
import javax.ws.rs.core.MultivaluedMap;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Encapsulating common header and role parsing.
 */
abstract class HeaderRoleUtil {
    private static final Logger LOG = LoggerFactory.getLogger(HeaderRoleUtil.class);

    static Optional<String> headerValue(MultivaluedMap<String, String> headers, @Nullable String headerName) {
        if (headerName == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(headers.getFirst(headerName.toLowerCase()));
    }

    static Optional<List<String>> headerValues(MultivaluedMap<String, String> headers,
                                                         @Nullable String headerNamePrefix) {
        if (headerNamePrefix == null) {
            return Optional.empty();
        }
        Set<String> keys = headers.keySet();
        List<String> headerValues = keys.stream().filter(key -> key.startsWith(headerNamePrefix.toLowerCase()))
                .map(key -> headers.getFirst(key)).collect(Collectors.toList());

        return Optional.ofNullable(headerValues);
    }

    static @NotNull Set<String> csv(@NotNull List<String> values) {
        Set<String> uniqValues = new HashSet<>();
        for (String csString : values) {
            String[] valueArr = csString.split(",");

            for (String value : valueArr) {
                uniqValues.add(value.trim());
            }
        }
        return uniqValues;
    }

    static @NotNull Set<String> getRoleIds(RoleService roleService, @NotNull Set<String> roleNames) {
        Set<String> roleIds = new HashSet<>();
        for (String roleName : roleNames) {
            if (roleService.exists(roleName)) {
                try {
                    Role r = roleService.load(roleName);
                    roleIds.add(r.getId());
                } catch (NotFoundException e) {
                    LOG.error("Role {} not found, but it existed before", roleName);
                }
            }
        }
        return roleIds;
    }

}
