package b_c.unbearable.messages.utils;

import b_c.unbearable.messages.utils.In;
import b_c.unbearable.messages.utils.Out;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 *
 */
public class InNOutTest
{
    @Test
    public void lotsOfJunk() throws Exception
    {
        int one = 9;
        int two = 4;
        byte[] first = new byte[] {-1 , 33, 8, 1, 2};
        int three = 1977;
        byte[] second = new byte[] {77};
        int four = 96;
        byte[] third = new byte[0];
        int five = 250;
        int six = 2;
        int seven = 23456;
        int eight = 255;

        Out out = new Out();
        out.putOneByteInt(one);
        out.putOneByteInt(two);
        out.putOneByteOfBytes(first);
        out.putTwoByteInt(three);
        out.putTwoBytesOfBytes(second);
        out.putTwoByteInt(four);
        out.putOneByteOfBytes(third);
        out.putTwoByteInt(five);
        out.putOneByteInt(six);
        out.putTwoByteInt(seven);
        out.putOneByteInt(eight);

        In in = new In(out.toByteArray());
        assertThat(in.readOneByteInt(), equalTo(one));
        assertThat(in.readOneByteInt(), equalTo(two));
        assertThat(in.readOneByteOfBytes(), equalTo(first));
        assertThat(in.readTwoByteInt(), equalTo(three));
        assertThat(in.readTwoBytesOfBytes(), equalTo(second));
        assertThat(in.readTwoByteInt(), equalTo(four));
        assertThat(in.readOneByteOfBytes(), equalTo(third));
        assertThat(in.readTwoByteInt(), equalTo(five));
        assertThat(in.readOneByteInt(), equalTo(six));
        assertThat(in.readTwoByteInt(), equalTo(seven));
        assertThat(in.readOneByteInt(), equalTo(eight));

    }
}
