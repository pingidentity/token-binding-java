package b_c.unbearable.messages;

import b_c.unbearable.JceProviderTestSupport;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 *
 */
public class TokenBindingKeyParametersTest
{
    @Test
    public void testSupportedAndAvailable() throws Exception
    {
        TokenBindingKeyParameters tbkp = TokenBindingKeyParameters.fromIdentifier(TokenBindingKeyParameters.ECDSAP256);
        assertTrue(tbkp.isSupportedAndAvailable());

        tbkp = TokenBindingKeyParameters.fromIdentifier(TokenBindingKeyParameters.RSA2048_PKCS1_5);
        assertTrue(tbkp.isSupportedAndAvailable());

        tbkp = TokenBindingKeyParameters.fromIdentifier(TokenBindingKeyParameters.RSA2048_PSS);
        assertFalse(tbkp.isSupportedAndAvailable());

        JceProviderTestSupport support = new JceProviderTestSupport();

        support.runWithBouncyCastleProvider(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                TokenBindingKeyParameters tbkp = TokenBindingKeyParameters.fromIdentifier(TokenBindingKeyParameters.ECDSAP256);
                assertTrue(tbkp.isSupportedAndAvailable());

                tbkp = TokenBindingKeyParameters.fromIdentifier(TokenBindingKeyParameters.RSA2048_PKCS1_5);
                assertTrue(tbkp.isSupportedAndAvailable());

                tbkp = TokenBindingKeyParameters.fromIdentifier(TokenBindingKeyParameters.RSA2048_PSS);
                assertTrue(tbkp.isSupportedAndAvailable());
            }
        });
    }
}
