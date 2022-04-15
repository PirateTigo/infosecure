package ru.sibsutis.security.net;

import org.apache.commons.lang3.tuple.Pair;
import ru.sibsutis.security.encrypt.CryptoUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

public class ShamirCommunicator {

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

    public void init(BigInteger p) {
        Pair<BigInteger, BigInteger> shamirPair = CryptoUtils.generateShamir(p);
        c = shamirPair.getLeft();
        d = shamirPair.getRight();
        this.p = p;
    }

    public void startSending() {
        messageStream = new ByteArrayOutputStream();
        messageHasGot = false;
        System.out.println("Start sending message...");
    }

    public void sendMessage(ByteArrayInputStream messageStream, ShamirCommunicator dst) {
        int messageChunk = messageStream.read();
        dst.startSending();
        while (messageChunk != -1) {
            sendMessage(messageChunk, dst);
            messageChunk = messageStream.read();
        }
        dst.stopSending();
    }

    public BigInteger firstStep(BigInteger x1) {
        return x1.modPow(c, p);
    }

    public void secondStep(BigInteger x3) {
        BigInteger message = x3.modPow(d, p);
        messageStream.write(message.intValue());
    }

    public void stopSending() {
        messageHasGot = true;
        System.out.println("Message has got");
    }

    public boolean hasMessageGot() {
        return messageHasGot;
    }

    public ByteArrayOutputStream getMessageStream() {
        return messageStream;
    }

    private void sendMessage(int message, ShamirCommunicator dst) {
        BigInteger p = CryptoUtils.generateRandomPrime(this.pLength, 256);
        init(p);
        dst.init(p);
        BigInteger x1 = BigInteger.valueOf(message).modPow(c, p);
        BigInteger x2 = dst.firstStep(x1);
        BigInteger x3 = x2.modPow(d, p);
        dst.secondStep(x3);
    }

}
