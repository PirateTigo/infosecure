package ru.sibsutis.security.net;

import ru.sibsutis.security.cli.CliProcessor;
import ru.sibsutis.security.encrypt.GOST94Digester;
import ru.sibsutis.security.encrypt.ShamirCommunicator;

import javax.naming.OperationNotSupportedException;

public final class EntityFactory {
    private final CliProcessor cliProcessor;
    private final CipherScheme cipherScheme;
    private final SignatureScheme signatureScheme;

    public EntityFactory(CliProcessor cliProcessor) {
        this.cliProcessor = cliProcessor;
        cipherScheme = cliProcessor.getCipherScheme();
        signatureScheme = cliProcessor.getSignature();
        if (cliProcessor.isVerbose()) {
            System.out.printf("Cryptor: cipher scheme '%s'%n", cipherScheme.getCode());
            if (signatureScheme != null) {
                System.out.printf("Cryptor: signature scheme '%s'%n", signatureScheme.getCode());
            }
        }
    }

    public Communicator createCommunicator()throws OperationNotSupportedException {
        switch (cipherScheme) {
            case SHAMIR:
                return createShamirCommunicator();
            default:
                throw new OperationNotSupportedException(
                        String.format("Communicator for '%s' cipher scheme was not realized", cipherScheme.getCode())
                );
        }
    }

    public Digester createDigester() throws OperationNotSupportedException {
        switch (signatureScheme) {
            case GOST_34_10_94:
                return createGOST94Digester();
            default:
                throw new OperationNotSupportedException(
                        String.format("Digester for '%s' signature scheme was not realized", signatureScheme.getCode())
                );
        }
    }

    private Communicator createShamirCommunicator() {
        int pLength = cliProcessor.getSPLength();
        if (pLength < 0) {
            throw new IllegalStateException("Incorrect 'sp' parameter");
        }
        return new ShamirCommunicator(pLength);
    }

    private Digester createGOST94Digester() {
        return new GOST94Digester(
                cliProcessor.getGostPLength(),
                cliProcessor.getGostQLength(),
                cliProcessor.isVerbose()
        );
    }
}
