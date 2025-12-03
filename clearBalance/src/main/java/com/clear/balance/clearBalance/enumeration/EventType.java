package com.clear.balance.clearBalance.enumeration;

public enum EventType {
    LOGIN_ATTEMPT("You tried to log in"),
    LOGIN_ATTEMPT_FAILURE("You tried to log in and you failed"),
    LOGIN_ATTEMPT_SUCCESS("You tried to log in and you succeeded"),
    PROFILE_UPDATE("You updated your profile information"),
    PROFILE_PICTURE_UPDATE("You updated your profile picture"),
    ROLE_UPDATE("You updated your role and permissions"),
    ACCOUNT_SETTINGS_UPDATE("You updated your account settings"),
    MFA_UPDATE("You updated your MFA settings"),
    PASSWORD_UPDATE("You updated your password");

    private final String description;

    EventType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return this.description;
    }
}