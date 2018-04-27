package com.pingidentity.oss.unbearable.utils;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

/**
 *
 */
public class UtilTest
{
    @Test
    public void testFromIntAndBack() throws Exception
    {
        for (int i = 0; i < 256; i++)
        {
            byte b = Util.byteFromInt(i);
            int anInt = Util.intFromByte(b);
            assertThat(i, equalTo(anInt));
        }
    }

    @Test
    public void testFromByteAndBack() throws Exception
    {
        for (byte b = Byte.MIN_VALUE; ; b++)
        {
            int i = Util.intFromByte(b);
            byte aByte = Util.byteFromInt(i);
            assertThat(b, equalTo(aByte));
            if (b == Byte.MAX_VALUE)
            {
                break;
            }
        }
    }

    @Test
    public void testFewMoreByteInt()
    {
        assertThat(0, equalTo(Util.intFromByte((byte) 0)));
        assertThat(127, equalTo(Util.intFromByte((byte) 127)));
        assertThat(128, equalTo(Util.intFromByte((byte) -128)));
        assertThat(255, equalTo(Util.intFromByte((byte) -1)));

        assertThat((byte)-1, equalTo(Util.byteFromInt(255)));
        assertThat((byte)0, equalTo(Util.byteFromInt(0)));
        assertThat((byte)-120, equalTo(Util.byteFromInt(136)));
    }

    @Test (expected = IllegalArgumentException.class)
    public void testOutOfRange1()
    {
        byte b = Util.byteFromInt(-1);
    }

    @Test (expected = IllegalArgumentException.class)
    public void testOutOfRange2()
    {
        byte b = Util.byteFromInt(256);
    }

    @Test (expected = IllegalArgumentException.class)
    public void testOutOfRange3()
    {
        byte b = Util.byteFromInt(846941);
    }
}
