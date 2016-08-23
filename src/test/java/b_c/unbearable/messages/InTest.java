package b_c.unbearable.messages;

import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;


/**
 *
 */
public class InTest
{  
    @Test
    public void readSomeThingsAndMarkAndRead() throws IOException
    {
        byte[] inBytes = new byte[] {16,0,5,1,2,3,4,5,6,1,1,1,0,1,1};
        In in = new In(inBytes);
        assertThat(16, equalTo(in.readOneByteInt()));
        in.mark();
        byte[] bytes = in.readTwoBytesOfBytes();
        assertThat(5, equalTo(bytes.length));
        assertThat(new byte[] {1,2,3,4,5}, equalTo(bytes));
        assertThat(6, equalTo(in.readOneByteInt()));
        bytes = in.readOneByteOfBytes();
        assertThat(1, equalTo(bytes.length));
        assertThat((byte)1, equalTo(bytes[0]));
        bytes = in.readBytesFromMark();
        assertThat(Util.subArray(inBytes, 1, 10), equalTo(bytes));
        assertThat(256, equalTo(in.readTwoByteInt()));
        assertThat(257, equalTo(in.readTwoByteInt()));
    }

    @Test
    public void simpleRead()  throws IOException
    {
        // a -08 TBPROTO TLS extension, which this code will never see 'cause it's
        // at the TLS layer but it's a 'real' example
        In in = new In(new byte[]{0, 24, 0, 4, 0, 8, 1, 2});
        assertThat(24, equalTo(in.readTwoByteInt()));  // type
        assertThat(4, equalTo(in.readTwoByteInt()));   // length
        assertThat(0, equalTo(in.readOneByteInt()));   // major version
        assertThat(8, equalTo(in.readOneByteInt()));   // minor version
        assertThat(new byte[] {2}, equalTo(in.readOneByteOfBytes())); // key_parameters_list w/ just ecdsap256(2)
    }
}
