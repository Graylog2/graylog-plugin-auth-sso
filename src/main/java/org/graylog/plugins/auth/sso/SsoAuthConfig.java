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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;

import javax.annotation.Nullable;

@AutoValue
@JsonDeserialize(builder = AutoValue_SsoAuthConfig.Builder.class)
@JsonAutoDetect
public abstract class SsoAuthConfig {

    public static Builder builder() {
        return new AutoValue_SsoAuthConfig.Builder();
    }

    public abstract Builder toBuilder();

    public static SsoAuthConfig defaultConfig(String trustedProxies) {
        return builder()
                .usernameHeader("Remote-User")
                .autoCreateUser(true)
                .requireTrustedProxies(true)
                .trustedProxies(trustedProxies)
                .rolesHeader("Roles")
                .syncRoles(false)
                .build();
    }

    @JsonProperty("username_header")
    public abstract String usernameHeader();

    @JsonProperty("fullname_header")
    @Nullable
    public abstract String fullnameHeader();

    @JsonProperty("email_header")
    @Nullable
    public abstract String emailHeader();

    @JsonProperty("default_group")
    @Nullable
    public abstract String defaultGroup();

    @JsonProperty("auto_create_user")
    public abstract boolean autoCreateUser();

    @JsonProperty("require_trusted_proxies")
    public abstract boolean requireTrustedProxies();

    @JsonProperty("trusted_proxies")
    @Nullable
    public abstract String trustedProxies();

    @JsonProperty("default_email_domain")
    @Nullable
    public abstract String defaultEmailDomain();
    
    @JsonProperty("sync_roles")
    public abstract boolean syncRoles();

    @JsonProperty("roles_header")
    @Nullable
    public abstract String rolesHeader();
    
    @AutoValue.Builder
    public static abstract class Builder {
        abstract SsoAuthConfig build();

        @JsonProperty("username_header")
        public abstract Builder usernameHeader(String usernameHeader);

        @JsonProperty("fullname_header")
        public abstract Builder fullnameHeader(@Nullable String fullnameHeader);

        @JsonProperty("email_header")
        public abstract Builder emailHeader(@Nullable String emailHeader);

        @JsonProperty("default_group")
        public abstract Builder defaultGroup(@Nullable String defaultGroup);

        @JsonProperty("auto_create_user")
        public abstract Builder autoCreateUser(boolean autoCreateUser);

        @JsonProperty("require_trusted_proxies")
        public abstract Builder requireTrustedProxies(boolean requireTrustedProxies);

        @JsonProperty("trusted_proxies")
        public abstract Builder trustedProxies(@Nullable String trustedProxies);

        @JsonProperty("default_email_domain")
        public abstract Builder defaultEmailDomain(@Nullable String defaultEmailDomain);
        
        @JsonProperty("sync_roles")
        public abstract Builder syncRoles(boolean syncRoles);
        
        @JsonProperty("roles_header")
        public abstract Builder rolesHeader(@Nullable String rolesHeader);


    }
}

