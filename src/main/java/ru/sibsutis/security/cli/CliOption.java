package ru.sibsutis.security.cli;

import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

import java.util.Arrays;

public enum CliOption {
    MESSAGE("m", "message",
            true, "Message to encryption"),
    FILE("f", "file",
            true, "Path to the file to be encrypted"),
    CYPHER("c", "cipher",
            true, "Cipher type. Use one of next values:\n" +
            "sha - Shamir scheme"),
    SHAMIR_P_LENGTH("sp", "spLength",
            true, "Bit count to P parameter Shamir Scheme"),
    OUTPUT("o", "output",
            true, "Output file path"),
    GOST_Q_LENGTH("gostq", "gostqLength",
            true, "Bit count to Q parameter DSA (GOST R34.10-94)"),
    GOST_P_LENGTH("gostp", "gostpLength",
            true, "Bit count to P parameter DSA (GOST R34.10-94)"),
    SIGNATURE("s", "signature",
            true, "Signature type. Use on of next values:\n" +
            "gost34.10-94 - GOST R34.10-94 scheme"),
    VERBOSE("v", "verbose",
            false, "Output of the details of the encryption process"),
    HELP("h", "help",
            false, "Show with help information");

    private final Option option;

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
