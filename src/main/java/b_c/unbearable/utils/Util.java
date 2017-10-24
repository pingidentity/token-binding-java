package b_c.unbearable.utils;

import java.math.BigInteger;

/**
 *
 */
public class Util
{
    public static byte[] subArray(byte[] inputBytes, int startPos, int length)
    {
        byte[] subArray = new byte[length];
        System.arraycopy(inputBytes, startPos, subArray, 0, subArray.length);
        return subArray;
    }

    public static byte[] leftHalf(byte[] inputBytes)
    {
        return subArray(inputBytes, 0, (inputBytes.length / 2));
    }

    public static byte[] rightHalf(byte[] inputBytes)
    {
        int half = inputBytes.length / 2;
        return subArray(inputBytes, half, half);
    }

    public static int intFromByte(byte b)
    {
        return (b & 0xff);
    }

    public static byte byteFromInt(int i)
    {
        if (i < 0 || i > 255)
        {
            throw new IllegalArgumentException("int value " +i+ " out of the range (0 - 255) to convert to a single byte.");
        }
        return (byte) i;
    }

    public static byte[] concat(byte[]... byteArrays)
    {
        int size = totalLength(byteArrays);
        Out out = new Out(size);
        for (byte[] bytes : byteArrays)
        {
            out.write(bytes);
        }
        return out.toByteArray();
    }

    public static int totalLength(byte[]... byteArrays)
    {
        int size = 0;
        for (byte[] bytes : byteArrays)
        {
            size = size + bytes.length;
        }
        return size;
    }

    public static byte[] signatureInput(byte tokenBingingType, byte tokenBindingKeyParams, byte[] ekm)
    {
        Out out = new Out(ekm.length + 2);
        out.write(tokenBingingType);
        out.write(tokenBindingKeyParams);
        out.write(ekm);
        return out.toByteArray();
    }

    public static byte[] toUnsignedMagnitudeByteArray(BigInteger bigInteger, int minArrayLength)
    {
        byte[] bytes = toUnsignedMagnitudeByteArray(bigInteger);
        if (minArrayLength > bytes.length)
        {
            bytes = concat(new byte[minArrayLength - bytes.length], bytes);
        }
        return bytes;
    }

    public static byte[] toUnsignedMagnitudeByteArray(BigInteger bigInteger)
    {
        if (bigInteger.signum() < 0)
        {
            String msg = "Cannot convert negative values to an unsigned magnitude byte array: " + bigInteger;
            throw new IllegalArgumentException(msg);
        }

        byte[] twosComplementBytes = bigInteger.toByteArray();
        byte[] magnitude;

        if ((bigInteger.bitLength() % 8 == 0) && (twosComplementBytes[0] == 0) && twosComplementBytes.length > 1)
        {
            magnitude = subArray(twosComplementBytes, 1, twosComplementBytes.length - 1);
        }
        else
        {
            magnitude = twosComplementBytes;
        }

        return magnitude;
    }

    public static BigInteger bigInt(byte[] magnitude)
    {
        final int signumPositive = 1;
        return new BigInteger(signumPositive, magnitude);
    }
}
