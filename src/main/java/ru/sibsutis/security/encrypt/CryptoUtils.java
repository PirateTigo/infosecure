package ru.sibsutis.security.encrypt;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;

import java.math.BigInteger;
import java.util.Random;

public final class CryptoUtils {

    private static final long WAIT_TIMEOUT = 5000L; // 5 seconds

    private CryptoUtils() {}

    public static BigInteger secretKey(BigInteger fromPrivateKey, BigInteger toPublicKey, BigInteger module) {
        return toPublicKey.modPow(fromPrivateKey, module);
    }

    public static BigInteger generateRandomPrime(int pLength, int minValue) {
        long timeMark = System.currentTimeMillis();
        Random random = new Random(timeMark);
        BigInteger p;
        BigInteger minValueBI = BigInteger.valueOf(minValue);

        while (true) {
            if (System.currentTimeMillis() - timeMark > WAIT_TIMEOUT) {
                throw new IllegalStateException("Shamir scheme waiting time out");
            }
            p = BigInteger.probablePrime(pLength, random);
            if (p.compareTo(minValueBI) < 0) {
                continue;
            }
            break;
        }
        return p;
    }

    public static Pair<BigInteger, BigInteger> generateShamir(BigInteger p) {
        BigInteger one = new BigInteger("1");
        BigInteger pMinusOne = p.subtract(one);

        BigInteger c;
        BigInteger d;

        long timeMark = System.currentTimeMillis();
        Random random = new Random(timeMark);

        while (true) {
            if (System.currentTimeMillis() - timeMark > WAIT_TIMEOUT) {
                throw new IllegalStateException("Shamir scheme waiting time out");
            }
            c = new BigInteger(pMinusOne.bitLength(), random);
            if (!c.gcd(pMinusOne).equals(one)) {
                continue;
            }
            d = c.modInverse(pMinusOne);
            break;
        }
        return new ImmutablePair<>(c, d);
    }

    public static Triple<BigInteger, BigInteger, BigInteger> generateDiffieHellman(
            int qLength,
            int pLength,
            int b,
            int certainty) {
        BigInteger p;
        BigInteger q;
        BigInteger g;

        BigInteger one = new BigInteger("1");
        BigInteger bValue = new BigInteger(String.valueOf(b));
        BigInteger pMinusOne;

        Random random = new Random(System.currentTimeMillis());
        long timeMark = System.currentTimeMillis();

        while (true) {
            if (System.currentTimeMillis() - timeMark > WAIT_TIMEOUT) {
                throw new IllegalStateException("Diffie Hellman scheme waiting time out");
            }
            q = BigInteger.probablePrime(qLength, random);
            p = q.multiply(bValue).add(one);
            if (!p.isProbablePrime(certainty)) {
                continue;
            }
            pMinusOne = p.subtract(one);

            while (true) {
                if (System.currentTimeMillis() - timeMark > WAIT_TIMEOUT) {
                    throw new IllegalStateException("Diffie Hellman waiting time out");
                }
                g = new BigInteger(pLength - 1, random);
                if (one.compareTo(g) < 0
                        && g.compareTo(pMinusOne) < 0
                        && !(g.modPow(q, p).equals(one))) {
                    // g has found
                    break;
                }
            }
            // p and q have found
            break;
        }

        return new ImmutableTriple<>(p, q, g);
    }

}
