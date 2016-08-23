package b_c.unbearable.messages;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 *
 */
public class In extends ByteArrayInputStream
{
    private static final byte[] EMPTY = new byte[0];

    In(byte[] buf)
    {
        super(buf);
    }

    public int readOneByteInt() throws IOException
    {
        return read();
    }

    public int readTwoByteInt() throws IOException
    {
        return (readOneByteInt() << 8) | readOneByteInt();
    }

    byte[] readOneByteOfBytes() throws IOException
    {
        int len = readOneByteInt();
        return readBytes(len);
    }

    public byte[] readTwoBytesOfBytes() throws IOException
    {
        int len = readTwoByteInt();
        return readBytes(len);
    }

    public void mark()
    {
        // the parameter has no meaning for mark(int readAheadLimit) in ByteArrayInputStream
        mark(Integer.MIN_VALUE);
    }

    public byte[] readBytesFromMark() throws IOException
    {
        int len = pos - mark;
        reset();
        return readBytes(len);
    }

    private byte[] readBytes(int length) throws IOException
    {
        checkLength(length);
        byte[] bytes = EMPTY;
        if (length != 0)
        {
            bytes = new byte[length];
            int howMany = read(bytes, 0, length);
            if (howMany != length)
            {
                throw new IOException("Needed to read " + length + " but only able to read " + howMany);
            }
        }

        return bytes;
    }

    private void checkLength(int len) throws IOException
    {
        int available = available();
        if (len > available)
        {
            throw new IOException("Indicated length " + len + " exceeds available bytes " + available);
        }
    }
}