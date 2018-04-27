package com.pingidentity.oss.unbearable.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *
 */
public class Out extends ByteArrayOutputStream
{
    private static final byte[] EMPTY = new byte[0];

    public Out()
    {
        super();
    }

    public Out(int size)
    {
        super(size);
    }

    public void putOneByteInt(int i)
    {
        if (i >= 256)
        {
            throw new IllegalArgumentException("Integer value " + i +" is too big to be represented in one byte.");
        }

        write(i);
    }

    public void putTwoByteInt(int i)
    {
        if (i >= 65536)
        {
            throw new IllegalArgumentException("Integer value " + i +" is too big to be represented in two bytes.");
        }
        write(i >> 8);
        write(i);
    }

    public void putOneByteOfBytes(byte[] bytes)
    {
        if (bytes == null)
        {
            bytes = EMPTY;
        }
        putOneByteInt(bytes.length);
        write(bytes, 0, bytes.length);
    }

    public void putTwoBytesOfBytes(byte[] bytes)
    {
        if (bytes == null)
        {
            bytes = EMPTY;
        }
        putTwoByteInt(bytes.length);
        write(bytes, 0, bytes.length);
    }

    @Override
    public void write(byte[] b)
    {
        try
        {
            super.write(b);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("ByteArrayOutputStream should never throw an IOException but...", e);

        }
    }
}
