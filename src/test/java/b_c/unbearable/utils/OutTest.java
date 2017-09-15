package b_c.unbearable.utils;

import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 *
 */
public class OutTest
{
    @Test
    public void oneByteInt() throws Exception
    {
        Out out = new Out();
        out.putOneByteInt(16);
        byte[] bytes = out.toByteArray();
        assertThat(bytes.length, equalTo(1));
        byte value = 16;
        assertThat(bytes[0], equalTo(value));

        out.reset();

        out.putOneByteInt(255);
        assertThat(bytes.length, equalTo(1));
        bytes = out.toByteArray();
        value = (byte) 255;
        assertThat(bytes[0], equalTo(value));
    }

    @Test
    public void twoByteInt() throws Exception
    {
        Out out = new Out();
        out.putTwoByteInt(16);
        byte[] bytes = out.toByteArray();
        assertThat(bytes.length, equalTo(2));
        byte value = 16;
        assertThat(bytes[1], equalTo(value));
        value = 0;
        assertThat(bytes[0], equalTo(value));

        out.reset();

        out.putTwoByteInt(65535);
        bytes = out.toByteArray();
        value = (byte) 255;
        assertThat(bytes[1], equalTo(value));
        assertThat(bytes[0], equalTo(value));
    }

    @Test (expected = IOException.class)
    public void oneByteIntTooBig() throws Exception
    {
        Out out = new Out();
        out.putOneByteInt((int) Math.pow(2,8));
    }

    @Test (expected = IOException.class)
    public void twoByteIntTooBig() throws Exception
    {
        Out out = new Out();
        out.putTwoByteInt((int) Math.pow(2,16));
    }


    @Test
    public void oneByteOfBytesInt() throws IOException
    {
        Out out = new Out();
        byte[] stuff = new byte[15];
        Arrays.fill(stuff, (byte)7);
        out.putOneByteOfBytes(stuff);
        byte[] outBytes = out.toByteArray();
        assertThat(outBytes.length, equalTo(16));
        byte value = 15;
        assertThat(outBytes[0], equalTo(value));
        value = 7;
        for (int i = 1 ; i < outBytes.length; i++)
        {
            assertThat(outBytes[i], equalTo(value));
        }
    }

    @Test (expected = IOException.class)
    public void oneByteOfBytesOneTooMany() throws Exception
    {
        Out out = new Out();
        out.putOneByteOfBytes(new byte[256]);
    }

    @Test (expected = IOException.class)
    public void oneByteOfBytesLotsTooMany() throws Exception
    {
        Out out = new Out();
        out.putOneByteOfBytes(new byte[399]);
    }

    @Test (expected = IOException.class)
    public void twoBytesOfBytesOneTooMany() throws Exception
    {
        Out out = new Out();
        out.putTwoBytesOfBytes(new byte[65536]);
    }

    @Test
    public void twoBytesOfBytesEmpty() throws Exception
    {
        Out out = new Out();
        out.putTwoBytesOfBytes(new byte[0]);
        byte[] bytes = out.toByteArray();

        byte value = (byte) 0;
        assertThat(bytes[1], equalTo(value));
        assertThat(bytes[0], equalTo(value));

        out.putTwoBytesOfBytes(null);
        bytes = out.toByteArray();
        assertThat(bytes[1], equalTo(value));
        assertThat(bytes[0], equalTo(value));
    }

    @Test
    public void oneByteOfBytesEmpty() throws Exception
    {
        Out out = new Out();
        out.putOneByteOfBytes(new byte[0]);
        byte[] bytes = out.toByteArray();

        byte value = (byte) 0;
        assertThat(bytes[0], equalTo(value));

        out.putTwoBytesOfBytes(null);
        bytes = out.toByteArray();
        assertThat(bytes[0], equalTo(value));
    }


}
