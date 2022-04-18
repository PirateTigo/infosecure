package ru.sibsutis.security.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.io.FileUtils;
import ru.sibsutis.security.net.CipherScheme;
import ru.sibsutis.security.net.SignatureScheme;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
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
                System.out.printf("Cryptor: source message '%s'%n", message);
            }
            byte[] messageBytes = message.getBytes(UTF_8);
            return bytesToInputStream(messageBytes);
        }

        if (commandLine.hasOption(CliOption.FILE.getOption())) {
            String fileName = commandLine.getOptionValue(CliOption.FILE.getOption());
            Path fileToEncryptionPath = Paths.get(fileName).toAbsolutePath();
            try {
                byte[] messageBytes = FileUtils.readFileToByteArray(fileToEncryptionPath.toFile());
                ByteArrayInputStream result = bytesToInputStream(messageBytes);
                if (isVerbose()) {
                    System.out.printf("Cryptor: source message file '%s'%n", fileToEncryptionPath);
                }
                return result;
            } catch (IOException e) {
                System.out.printf("Cryptor: cannot read message from file '%s'%n", fileName);
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
                return CipherScheme.fromCode(cipherCode);
            } catch (Exception ex) {
                System.out.printf("Cryptor: unknown cipher scheme '%s'%n", cipherCode);
                if (isVerbose()) {
                    ex.printStackTrace();
                }
            }
        }
        return CipherScheme.SHAMIR;
    }

    public boolean isNeedDigest() {
        return commandLine.hasOption(CliOption.SIGNATURE.getOption());
    }

    public SignatureScheme getSignature() {
        if (isNeedDigest()) {
            return SignatureScheme.fromCode(commandLine.getOptionValue(CliOption.SIGNATURE.getOption()));
        } else {
            return null;
        }
    }

    public int getSPLength() {
        int pLength = getIntValue(CliOption.SHAMIR_P_LENGTH, 1);
        return pLength < 1 ? -1 : pLength;
    }

    public FileOutputStream getOutputFileStream() {
        if (commandLine.hasOption(CliOption.OUTPUT.getOption())) {
            String fileName = commandLine.getOptionValue(CliOption.OUTPUT.getOption());
            Path outputFilePath = Paths.get(fileName).toAbsolutePath();
            try {
                FileOutputStream result = new FileOutputStream(outputFilePath.toString());
                if (isVerbose()) {
                    System.out.printf("Cryptor: output message file '%s'%n", outputFilePath);
                }
                return result;
            } catch (IOException e) {
                System.out.printf("Cryptor: cannot write message to file '%s'%n", fileName);
                if (commandLine.hasOption(CliOption.VERBOSE.getOption())) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    public int getGostQLength() {
        int qLength = getIntValue(CliOption.GOST_Q_LENGTH, 1);
        return qLength < 1 ? -1 : qLength;
    }

    public int getGostPLength() {
        int pLength = getIntValue(CliOption.GOST_P_LENGTH, 1);
        return pLength < 1 ? -1 : pLength;
    }

    public boolean isNeedHelp() {
        return commandLine.hasOption(CliOption.HELP.getOption());
    }

    private int getIntValue(CliOption option, int minValue) {
        if (commandLine.hasOption(option.getOption())) {
            String valueString = commandLine.getOptionValue(option.getOption());
            try {
                int value = Integer.parseInt(valueString);
                if (value < minValue) {
                    System.out.printf(
                            "Cryptor: incorrect %s value: %s",
                            option.getOption().getLongOpt(),
                            valueString
                    );
                    return minValue - 1;
                }
                return value;
            } catch (Exception ex) {
                System.out.printf(
                        "Cryptor: incorrect %s value: %s",
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

    private ByteArrayInputStream bytesToInputStream(byte[] bytes) {
        byte[] bytesWithSize = ByteBuffer
                .allocate(4 + bytes.length)
                .putInt(bytes.length)
                .put(bytes)
                .array();
        return new ByteArrayInputStream(bytesWithSize);
    }

}
