package ru.sibsutis.security.encrypt;

import com.google.common.math.BigIntegerMath;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.SecureRandom;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

public final class CryptoUtils {

    private static final long WAIT_TIMEOUT_10000 = 10000L; // 10 seconds
    private static final long WAIT_TIMEOUT_100 = 100L; // 100 ms

    private static final int MAX_BIT_COUNT = 1024;

    private static final BigInteger TWO = ONE.add(ONE);

    private static final int CERTAINTY = 100;

    private CryptoUtils() {}

    public static BigInteger generateRandom(int pLength, boolean prime) {
        SecureRandom random = new SecureRandom();
        if (prime) {
            return BigInteger.probablePrime(pLength, random);
        } else {
            return new BigInteger(pLength, random);
        }
    }

    public static BigInteger generateRandom(BigInteger minValue, BigInteger maxValue, boolean prime) {
        long timeMark = System.currentTimeMillis();
        SecureRandom random = new SecureRandom();
        BigInteger p;
        int minValueLength;

        if (minValue.compareTo(ZERO) < 0) {
            minValueLength = 0;
        } else {
            minValueLength = BigIntegerMath.log2(minValue, RoundingMode.FLOOR) + 1;
        }

        int maxValueLength;
        if (maxValue.compareTo(ZERO) < 0) {
            maxValueLength = 0;
        } else {
            maxValueLength = BigIntegerMath.log2(maxValue, RoundingMode.FLOOR) + 1;
        }
        if (minValueLength != 0 && maxValueLength != 0 && minValue.compareTo(maxValue) > 0) {
            return null;
        } else if (minValueLength == 0 && maxValueLength == 0) {
            return null;
        }
        int realLength;

        while (true) {
            if (System.currentTimeMillis() - timeMark > WAIT_TIMEOUT_10000) {
                throw new IllegalStateException("Random prime waiting time out");
            }
            if (minValueLength == maxValueLength) {
                realLength = minValueLength;
            } else {
                if (maxValueLength == 0 || maxValueLength > MAX_BIT_COUNT) {
                    realLength = minValueLength + random.nextInt(MAX_BIT_COUNT - minValueLength);
                } else {
                    realLength = minValueLength + random.nextInt(maxValueLength - minValueLength);
                }
                if (realLength < 2) {
                    continue;
                }
            }
            p = generateRandom(realLength, prime);
            if (minValue.compareTo(ZERO) >= 0 && p.compareTo(minValue) < 0) {
                continue;
            }
            if (maxValue.compareTo(ZERO) >= 0 && p.compareTo(maxValue) > 0) {
                continue;
            }
            break;
        }
        return p;
    }

    public static Pair<BigInteger, BigInteger> generateShamir(BigInteger p) {
        BigInteger pMinusOne = p.subtract(ONE);

        BigInteger c;
        BigInteger d;

        long timeMark = System.currentTimeMillis();

        while (true) {
            if (System.currentTimeMillis() - timeMark > WAIT_TIMEOUT_10000) {
                throw new IllegalStateException("Shamir scheme waiting time out");
            }
            c = generateRandom(pMinusOne.bitLength(), false);
            if (!c.gcd(pMinusOne).equals(ONE)) {
                continue;
            }
            d = c.modInverse(pMinusOne);
            break;
        }
        return new ImmutablePair<>(c, d);
    }

    public static Pair<Pair<BigInteger, BigInteger>, Pair<BigInteger, BigInteger>>
    generateGOSTParameters(int pLength, int qLength) {
        BigInteger b;
        BigInteger a;
        BigInteger p = null;
        BigInteger q;

        boolean found;
        long timeMarkCommon = System.currentTimeMillis();

        while (true) {
            if (System.currentTimeMillis() - timeMarkCommon > WAIT_TIMEOUT_10000) {
                throw new IllegalStateException("GOST parameters waiting time out");
            }
            q = generateRandom(qLength, true);
            found = false;
            b = TWO;
            while (b.multiply(q).bitLength() < pLength) {
                b = b.multiply(TWO);
            }
            BigInteger testExpression = b.multiply(q).add(ONE);
            while (testExpression.bitLength() == pLength) {
                if (testExpression.isProbablePrime(CERTAINTY)) {
                    found = true;
                    p = testExpression;
                    break;
                }
                b = b.add(ONE);
                testExpression = b.multiply(q).add(ONE);
            }
            if (found) {
                BigInteger g;
                a = TWO;
                found = false;
                long timeMarkForA = System.currentTimeMillis();

                while (true) {
                    if (System.currentTimeMillis() - timeMarkForA > WAIT_TIMEOUT_100) {
                        break;
                    }
                    g = generateRandom(pLength, false);
                    a = g.modPow(b, p);
                    if (a.compareTo(ONE) > 0) {
                        found = true;
                        break;
                    }
                }
                if (found) {
                    break;
                }
            }
        }

        return new ImmutablePair<>(new ImmutablePair<>(p, q), new ImmutablePair<>(b, a));
    }

}
