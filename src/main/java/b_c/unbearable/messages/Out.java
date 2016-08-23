package b_c.unbearable.messages;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 */
public class Out extends ByteArrayOutputStream
{
    private static final byte[] EMPTY = new byte[0];

    public void putOneByteInt(int i) throws IOException
    {
        if (i >= 256)
        {
            throw new IOException("Integer value " + i +" is too big to be represented in one byte.");
        }

        write(i);
    }

    public void putTwoByteInt(int i) throws IOException
    {
        if (i >= 65536)
        {
            throw new IOException("Integer value " + i +" is too big to be represented in two bytes.");
        }
        write(i >> 8);
        write(i);
    }

    public void putOneByteOfBytes(byte[] bytes) throws IOException
    {
        if (bytes == null)
        {
            bytes = EMPTY;
        }
        putOneByteInt(bytes.length);
        write(bytes, 0, bytes.length);
    }

    public void putTwoBytesOfBytes(byte[] bytes) throws IOException
    {
        if (bytes == null)
        {
            bytes = EMPTY;
        }
        putTwoByteInt(bytes.length);
        write(bytes, 0, bytes.length);
    }
}
