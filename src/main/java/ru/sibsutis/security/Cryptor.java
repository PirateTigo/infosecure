package ru.sibsutis.security;

import org.apache.commons.cli.*;
import ru.sibsutis.security.cli.CliOption;
import ru.sibsutis.security.cli.CliProcessor;
import ru.sibsutis.security.net.EntityFactory;
import ru.sibsutis.security.net.Sender;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;

public class Cryptor {

    public static void main(String[] args) {
        CommandLineParser parser = new DefaultParser(true);
        Options options = CliOption.getOptions();

        try {
            CommandLine commandLine = parser.parse(options, args);
            CliProcessor cliProcessor = new CliProcessor(commandLine);

            if (cliProcessor.isNeedHelp()) {
                showHelp(options);
                return;
            }

            boolean isVerbose = cliProcessor.isVerbose();

            Sender sender;

            try { // Send message
                EntityFactory entityFactory = new EntityFactory(cliProcessor);
                sender = Sender.builder()
                        .setNeedDigest(cliProcessor.isNeedDigest())
                        .setVerbose(isVerbose)
                        .build(entityFactory);
                sender.send(cliProcessor.getMessageStream());
            } catch (Exception ex) {
                System.out.println("Cryptor: Cannot send message");
                if (isVerbose) {
                    ex.printStackTrace();
                }
                return;
            }

            // Check out delivered message
            try (FileOutputStream outputStream = cliProcessor.getOutputFileStream()) {
                ByteArrayOutputStream deliveredMessageStream = sender.getSentMessageStream();
                if (outputStream != null) {
                    deliveredMessageStream.writeTo(outputStream);
                } else {
                    System.out.printf(
                            "Cryptor: Sent message: %s",
                            deliveredMessageStream.toString("UTF-8")
                    );
                }
            } catch (Exception ex) {
                System.out.println("Cryptor: Cannot check out delivered message");
                if (isVerbose) {
                    ex.printStackTrace();
                }
            }
        } catch (ParseException e) {
            showHelp(options);
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
