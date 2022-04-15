package ru.sibsutis.security;

import org.apache.commons.cli.*;
import ru.sibsutis.security.cli.CliOption;
import ru.sibsutis.security.cli.CliProcessor;
import ru.sibsutis.security.encrypt.CipherScheme;
import ru.sibsutis.security.net.ShamirCommunicator;

import javax.naming.OperationNotSupportedException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Cryptor {

    private static final int CERTAINTY = 100;

    public static void main(String[] args) {
        CommandLineParser parser = new DefaultParser(true);
        Options options = CliOption.getOptions();

        try {
            CommandLine commandLine = parser.parse(options, args);
            CliProcessor cliProcessor = new CliProcessor(commandLine);

            try (ByteArrayInputStream messageStream = cliProcessor.getMessageStream()) {
                if (messageStream == null) {
                    showHelp(options);
                    return;
                }

                try (ByteArrayOutputStream sentMessageStream = sendMessage(
                        messageStream,
                        cliProcessor,
                        options)) {
                    System.out.printf("Sent message: %s", sentMessageStream.toString(UTF_8.toString()));
                } catch (Exception e) {
                    System.out.println("Not encrypted");
                    if (cliProcessor.isVerbose()) {
                        e.printStackTrace();
                    }
                }
            } catch (IOException e) {
                System.out.println("Cannot close message input stream");
                if (cliProcessor.isVerbose()) {
                    e.printStackTrace();
                }
            }
        } catch (ParseException e) {
            showHelp(options);
        }
    }

    private static ByteArrayOutputStream sendMessage(
            ByteArrayInputStream message,
            CliProcessor cliProcessor,
            Options options) throws OperationNotSupportedException {
        CipherScheme cipherScheme = cliProcessor.getCipherScheme();
        switch (cipherScheme) {
            case SHAMIR:
                int pLength = cliProcessor.getSPLength();
                if (pLength < 0) {
                    showHelp(options);
                    throw new IllegalStateException("Incorrect parameters");
                }
                boolean isNeedSign = cliProcessor.isNeedSign();
                ShamirCommunicator client = new ShamirCommunicator(pLength);
                ShamirCommunicator server = new ShamirCommunicator(pLength);
                if (isNeedSign) {

                }
                client.sendMessage(message, server);
                if (server.hasMessageGot()) {
                    return server.getMessageStream();
                } else {
                    throw new IllegalStateException("Cannot send message to server");
                }
            case DIFFIE_HELLMAN:
                // TODO realize Diffie Hellman sending scheme
            default:
                throw new OperationNotSupportedException(
                        String.format("Scheme %s not realized", cipherScheme.getCode())
                );
        }
    }

    private static void showHelp(Options options) {
        HelpFormatter helpFormatter = new HelpFormatter();
        helpFormatter.printHelp(
                "cryptor [[OPTION] VALUE]",
                "You have to specify whether -m or -f option to encryption",
                options,
                "(c) Artem Tarakanovsky (piratetigo@gmail.com)"
        );
    }

}
