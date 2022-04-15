package ru.sibsutis.security.cli;

import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

import java.util.Arrays;

public enum CliOption {
    MESSAGE("m", "message",
            true, "Message to encryption"),
    FILE("f", "file",
            true, "Path to the file to be encrypted"),
    CYPHER("c", "cipher",true,
            "Cipher type. Use one of next values: \n" +
                    "sha - Shamir scheme"),
    SHAMIR_P_LENGTH("sp", "spLength",
            true, "Bit size to P parameter Shamir Scheme"),
    DIFFIE_HELLMAN_P_LENGTH("dhp", "dhpLength",
            true, "Bit size to P parameter Diffie Hellman Scheme"),
    DIFFIE_HELLMAN_Q_LENGTH("dhq", "dhqLength",
            true, "Bit size to Q parameter Diffie Hellman Scheme"),
    DIFFIE_HELLMAN_B_VALUE("dhb", "dhbValue",
            true, "Value to B parameter Diffie Hellman Scheme"),
    SIGNATURE("s", "sign",
            false, "Should it be signed"),
    VERBOSE("v", "verbose",
            false, "Output of the details of the encryption process");

    private Option option;

    CliOption(String name, String longName, boolean hasArg, String description) {
        option = new Option(name, longName, hasArg, description);
    }

    public Option getOption() {
        return option;
    }

    public static Options getOptions() {
        Options options = new Options();
        Arrays.stream(values()).map(CliOption::getOption).forEach(options::addOption);
        return options;
    }
}
