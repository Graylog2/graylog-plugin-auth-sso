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

    public static SsoAuthConfig defaultConfig() {
        return builder()
                .usernameHeader("Remote-User")
                .autoCreateUser(true)
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

    }
}

