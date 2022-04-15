package ru.sibsutis.security.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.io.FileUtils;
import ru.sibsutis.security.encrypt.CipherScheme;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CliProcessor {

    private final CommandLine commandLine;

    public CliProcessor(CommandLine commandLine) {
        this.commandLine = commandLine;
    }

    public ByteArrayInputStream getMessageStream() {
        if (commandLine.hasOption(CliOption.MESSAGE.getOption())) {
            String message = commandLine.getOptionValue(CliOption.MESSAGE.getOption());
            if (isVerbose()) {
                System.out.printf("Source message: %s%n", message);
            }
            byte[] bytes = message.getBytes(UTF_8);
            return new ByteArrayInputStream(bytes);
        }

        if (commandLine.hasOption(CliOption.FILE.getOption())) {
            String fileName = commandLine.getOptionValue(CliOption.FILE.getOption());
            Path fileToEncryptionPath = Paths.get(fileName).toAbsolutePath();
            try {
                ByteArrayInputStream result = new ByteArrayInputStream(
                        FileUtils.readFileToByteArray(fileToEncryptionPath.toFile())
                );
                if (isVerbose()) {
                    System.out.printf("Source message (file): %s%n", fileToEncryptionPath);
                }
                return result;
            } catch (IOException e) {
                System.out.printf("Cannot read message from file %s%n", fileName);
                if (commandLine.hasOption(CliOption.VERBOSE.getOption())) {
                    e.printStackTrace();
                }
            }

        }
        return null;
    }

    public boolean isVerbose() {
        return commandLine.hasOption(CliOption.VERBOSE.getOption());
    }

    public CipherScheme getCipherScheme() {
        if (commandLine.hasOption(CliOption.CYPHER.getOption())) {
            String cipherCode = commandLine.getOptionValue(CliOption.CYPHER.getOption());
            try {
                CipherScheme cipherScheme = CipherScheme.fromCode(cipherCode);
                if (isVerbose()) {
                    System.out.printf("Cipher scheme: %s%n", cipherScheme.getCode());
                }
                return cipherScheme;
            } catch (Exception ex) {
                System.out.printf("Unknown cipher scheme: %s%n", cipherCode);
                if (isVerbose()) {
                    ex.printStackTrace();
                }
            }
        }
        if (isVerbose()) {
            System.out.printf("Cipher scheme: %s%n", CipherScheme.SHAMIR.getCode());
        }
        return CipherScheme.SHAMIR;
    }

    public int getPLength() {
        int pLength = getIntValue(CliOption.DIFFIE_HELLMAN_P_LENGTH, 1);
        return pLength < 1 ? -1 : pLength;
    }

    public int getQLength() {
        int qLength = getIntValue(CliOption.DIFFIE_HELLMAN_Q_LENGTH, 1);
        return qLength < 1 ? -1 : qLength;
    }

    public int getBValue() {
        int bValue = getIntValue(CliOption.DIFFIE_HELLMAN_B_VALUE, 2);
        return bValue < 2 ? -1 : bValue;
    }

    public boolean isNeedSign() {
        return commandLine.hasOption(CliOption.SIGNATURE.getOption());
    }

    public int getSPLength() {
        int pLength = getIntValue(CliOption.SHAMIR_P_LENGTH, 1);
        return pLength < 1 ? -1 : pLength;
    }

    private int getIntValue(CliOption option, int minValue) {
        if (commandLine.hasOption(option.getOption())) {
            String valueString = commandLine.getOptionValue(option.getOption());
            try {
                int value = Integer.parseInt(valueString);
                if (value < minValue) {
                    System.out.printf(
                            "Incorrect %s value: %s",
                            option.getOption().getLongOpt(),
                            valueString
                    );
                    return minValue - 1;
                }
                if (isVerbose()) {
                    System.out.printf("%s: %s%n", option.getOption().getLongOpt(), valueString);
                }
                return value;
            } catch (Exception ex) {
                System.out.printf(
                        "Incorrect %s value: %s",
                        option.getOption().getLongOpt(),
                        valueString
                );
                if (isVerbose()) {
                    ex.printStackTrace();
                }
            }
        }
        return minValue - 1;
    }

}
