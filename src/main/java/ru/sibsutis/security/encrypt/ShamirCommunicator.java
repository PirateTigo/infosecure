package ru.sibsutis.security.encrypt;

import org.apache.commons.lang3.tuple.Pair;
import ru.sibsutis.security.net.Communicator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

public class ShamirCommunicator implements Communicator {

    private final int pLength;

    private BigInteger c;
    private BigInteger d;
    private BigInteger p;
    private ByteArrayOutputStream messageStream;
    private boolean messageHasGot;

    public ShamirCommunicator(int pLength) {
        this.pLength = pLength;
        messageHasGot = false;
    }

    public void sendMessage(ByteArrayInputStream messageStream, Communicator dst, boolean verbose) {
        BigInteger p = CryptoUtils.generateRandom(this.pLength, true);
        ShamirCommunicator shamirDst = (ShamirCommunicator) dst;
        shamirDst.startSending();
        if (verbose) {
            System.out.printf("Shamir scheme: p = %s%n", p);
        }

        long count = 1;
        int messageChunk;
        while ((messageChunk = messageStream.read()) != -1) {
            if (verbose) {
                System.out.printf("Shamir scheme: message %s = %s%n", count++, messageChunk);
            }
            sendMessage(messageChunk, shamirDst, p, verbose);
        }
        shamirDst.stopSending();
    }

    public boolean hasMessageGot() {
        return messageHasGot;
    }

    public ByteArrayOutputStream getMessageStream() {
        return messageStream;
    }

    private void init(BigInteger p, boolean verbose, boolean client) {
        Pair<BigInteger, BigInteger> shamirPair = CryptoUtils.generateShamir(p);
        c = shamirPair.getLeft();
        d = shamirPair.getRight();
        this.p = p;

        if (verbose) {
            System.out.printf("Shamir scheme: c = %s, d = %s (%s)%n", c, d, client ? "client" : "server");
        }
    }

    private void startSending() {
        messageStream = new ByteArrayOutputStream();
        messageHasGot = false;

        System.out.println("Shamir scheme: start sending message...");
    }

    private BigInteger firstStep(BigInteger x1, boolean verbose) {
        BigInteger x2 = x1.modPow(c, p);

        if (verbose) {
            System.out.printf("Shamir scheme: x2 = %s%n", x2);
        }

        return x2;
    }

    private void secondStep(BigInteger x3, boolean verbose) {
        BigInteger message = x3.modPow(d, p);
        messageStream.write(message.intValue());

        if (verbose) {
            System.out.printf("Shamir scheme: x4 = %s%n", message);
        }
    }

    private void stopSending() {
        messageHasGot = true;

        System.out.println("Shamir scheme: message has got");
    }

    private void sendMessage(int message, ShamirCommunicator dst, BigInteger p, boolean verbose) {
        init(p, verbose, true);
        dst.init(p, verbose, false);
        BigInteger x1 = BigInteger.valueOf(message).modPow(c, p);
        if (verbose) {
            System.out.printf("Shamir scheme: x1 = %s%n", x1);
        }
        BigInteger x2 = dst.firstStep(x1, verbose);
        BigInteger x3 = x2.modPow(d, p);
        if (verbose) {
            System.out.printf("Shamir scheme: x3 = %s%n", x3);
        }
        dst.secondStep(x3, verbose);
    }

}
