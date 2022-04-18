package ru.sibsutis.security.net;

public enum CipherScheme {
    SHAMIR("sha");

    private final String code;

    CipherScheme(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public static CipherScheme fromCode(String code) {
        switch (code.toLowerCase()) {
            case "sha":
                return SHAMIR;
            default:
                throw new IllegalArgumentException(
                        String.format("Incorrect cypher type: %s", code)
                );
        }
    }
}
