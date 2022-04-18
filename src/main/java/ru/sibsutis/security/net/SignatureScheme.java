package ru.sibsutis.security.net;

public enum SignatureScheme {
    GOST_34_10_94("gost34.10-94");

    private final String code;

    SignatureScheme(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    public static SignatureScheme fromCode(String code) {
        switch (code.toLowerCase()) {
            case "gost34.10-94":
                return GOST_34_10_94;
            default:
                throw new IllegalArgumentException(
                        String.format("Incorrect signature type: %s", code)
                );
        }
    }
}
