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

import org.junit.Test;

import javax.ws.rs.core.MultivaluedHashMap;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.*;

public class HeaderRoleUtilTest {

    @Test
    public void testHeaderValuesCsv() {
        MultivaluedHashMap<String, String> m = new MultivaluedHashMap<>();
        m.put("roles", Arrays.asList(new String[]{"role1, role2, role3"}));
        m.put("roles_1", Arrays.asList(new String[]{"asdf1"}));
        m.put("roles_2", Arrays.asList(new String[]{"asdf2"}));

        Optional<List<String>> s = HeaderRoleUtil.headerValues(m, "Roles");
        Set<String> actual = HeaderRoleUtil.csv(s.get());
        List<String> expected = Arrays.asList(new String[]{"role1","role2","role3","asdf1","asdf2"});

        assertEquals(actual.size(), expected.size());
        for ( String role : expected) {
            if ( !actual.contains(role)) {
                fail("Role [" + role + "] expected, but not in result: " + actual);
            }
        }

    }

}