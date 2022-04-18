package ru.sibsutis.security.encrypt;

import org.apache.commons.lang3.tuple.Pair;
import ru.sibsutis.security.net.Digester;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

public class GOST94Digester implements Digester {

    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger a;
    private final BigInteger y;
    private final BigInteger x;

    private final boolean verbose;

    public GOST94Digester(int pBitLength, int qBitLength, boolean verbose) {
        if (verbose) {
            System.out.println("GOST R34.10-94 digest: preparing...");
        }
        Pair<Pair<BigInteger, BigInteger>, Pair<BigInteger, BigInteger>> parameters =
                CryptoUtils.generateGOSTParameters(pBitLength, qBitLength);
        p = parameters.getLeft().getLeft();
        q = parameters.getLeft().getRight();
        BigInteger b = parameters.getRight().getLeft();
        a = parameters.getRight().getRight();
        x = CryptoUtils.generateRandom(ONE, q.subtract(ONE), false);
        y = a.modPow(x, p);
        this.verbose = verbose;
        if (verbose) {
            System.out.println("GOST R34.10-94 digest: prepared");
            System.out.printf("GOST R34.10-94 digest: q = %s%n", q);
            System.out.printf("GOST R34.10-94 digest: p = %s%n", p);
            System.out.printf("GOST R34.10-94 digest: b = %s%n", b);
            System.out.printf("GOST R34.10-94 digest: a = %s%n", a);
            System.out.printf("GOST R34.10-94 digest: x = %s%n", x);
            System.out.printf("GOST R34.10-94 digest: y = %s%n", y);
        }
    }

    public ByteArrayInputStream digest(ByteArrayInputStream messageStream) throws IOException {
        System.out.println("GOST R34.10-94 digest: signature calculation...");
        messageStream.mark(0);
        BigInteger hashValue = hash(messageStream, q, verbose);
        messageStream.reset();
        if (hashValue != null && hashValue.compareTo(ZERO) > 0) {
            if (verbose) {
                System.out.printf("GOST R34.10-94 digest: hash = %s%n", hashValue);
            }

            BigInteger qMinusOne = q.subtract(ONE);
            BigInteger k, r, s;
            while (true) {
                k = CryptoUtils.generateRandom(ONE, qMinusOne, false);
                if (k == null) {
                    continue;
                }
                r = a.modPow(k, p).mod(q);
                if (r.compareTo(ZERO) == 0) {
                    continue;
                }
                s = (k.multiply(hashValue).add(x.multiply(r))).mod(q);
                if (s.compareTo(ZERO) == 0) {
                    continue;
                }
                break;
            }

            System.out.println("GOST R34.10-94 digest: signature calculated");
            if (verbose) {
                System.out.printf("GOST R34.10-94 digest: r = %s%n", r);
                System.out.printf("GOST R34.10-94 digest: s = %s%n", s);
            }

            byte[] sourceMessage = new byte[messageStream.available()];
            messageStream.read(sourceMessage);
            messageStream.reset();
            byte[] rArray = r.toByteArray();
            byte[] sArray = s.toByteArray();
            ByteBuffer byteBuffer = ByteBuffer
                    .allocate(sourceMessage.length + 4 + rArray.length + 4 + sArray.length);
            byte[] signedMessage = byteBuffer
                    .put(sourceMessage)
                    .putInt(rArray.length)
                    .put(rArray)
                    .putInt(sArray.length)
                    .put(sArray)
                    .array();

            return new ByteArrayInputStream(signedMessage);
        }
        System.out.println("GOST R34.10-94 digest: signature calculation failed");
        return null;
    }

    public ByteArrayOutputStream verify(ByteArrayOutputStream messageStream) throws IOException {
        System.out.println("GOST R34.10-94 digest: signature verification...");
        // get message size
        byte[] fullMessage = messageStream.toByteArray();
        ByteBuffer fullMessageBuffer = ByteBuffer.wrap(fullMessage);
        IntBuffer intBuffer = fullMessageBuffer.asIntBuffer();
        int messageSize = intBuffer.get();

        // get message
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + messageSize)
                .putInt(messageSize)
                .put(fullMessage, 4, messageSize);
        ByteArrayOutputStream sentMessageStream = new ByteArrayOutputStream();
        sentMessageStream.write(byteBuffer.array());

        // get r size
        fullMessageBuffer.position(4 + messageSize);
        intBuffer = fullMessageBuffer.asIntBuffer();
        int rSize = intBuffer.get();

        // get r
        byte[] rArray = new byte[rSize];
        fullMessageBuffer.position(8 + messageSize);
        fullMessageBuffer.get(rArray);
        BigInteger r = new BigInteger(rArray);

        // get s size
        intBuffer = fullMessageBuffer.asIntBuffer();
        int sSize = intBuffer.get();

        // get s
        byte[] sArray = new byte[sSize];
        fullMessageBuffer.position(12 + messageSize + rSize);
        fullMessageBuffer.get(sArray);
        BigInteger s = new BigInteger(sArray);

        // check signature
        BigInteger hashValue = hash(new ByteArrayInputStream(sentMessageStream.toByteArray()), q, verbose);
        boolean isCorrect = false;
        if (hashValue != null) {
            if (r.compareTo(ZERO) > 0 && r.compareTo(q) < 0 && s.compareTo(ZERO) > 0 && s.compareTo(q) < 0) {
                BigInteger inverseHash = hashValue.modInverse(q);
                BigInteger u1 = inverseHash.multiply(s).mod(q);
                BigInteger minusR = r.multiply(new BigInteger("-1"));
                BigInteger u2 = minusR.multiply(inverseHash).mod(q);
                BigInteger v = a.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);
                if (v.compareTo(r) == 0) {
                    isCorrect = true;
                }
                if (verbose) {
                    System.out.printf("GOST R34.10-94 digest: h = %s%n", hashValue);
                    System.out.printf("GOST R34.10-94 digest: h^(-1) = %s%n", inverseHash);
                    System.out.printf("GOST R34.10-94 digest: r = %s%n", r);
                    System.out.printf("GOST R34.10-94 digest: s = %s%n", s);
                    System.out.printf("GOST R34.10-94 digest: u1 = %s%n", u1);
                    System.out.printf("GOST R34.10-94 digest: u2 = %s%n", u2);
                    System.out.printf("GOST R34.10-94 digest: v = %s%n", v);
                }
            }
        }

        System.out.printf("GOST R34.10-94 digest: signature is%s correct%n", isCorrect ? "" : "n't");
        return sentMessageStream;
    }

    private BigInteger hash(ByteArrayInputStream messageStream, BigInteger q, boolean verbose) {
        ByteArrayOutputStream signedMessage = new ByteArrayOutputStream();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");

            int data;
            while ((data = messageStream.read()) != -1) {
                signedMessage.write(data);
            }

            byte[] bytes = signedMessage.toByteArray();
            String digestStr = byteArrayToHexString(messageDigest.digest(bytes));
            BigInteger digestFull = new BigInteger(digestStr, 16);
            return digestFull.mod(q);
        } catch (NoSuchAlgorithmException e) {
            if (verbose) {
                e.printStackTrace();
            }
        }
        return null;
    }

    private String byteArrayToHexString(byte[] byteArray) {
        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray) {
            String str = Integer.toHexString(0xff & b);
            str = (str.length() == 1) ? "0" + str : str;
            sb.append(str);
        }
        return sb.toString();
    }

}
