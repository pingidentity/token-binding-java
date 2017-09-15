package b_c.unbearable.utils;

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
}
