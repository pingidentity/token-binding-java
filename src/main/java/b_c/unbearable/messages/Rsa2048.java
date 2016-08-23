package b_c.unbearable.messages;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 */
public abstract class Rsa2048 extends TokenBindingKeyParameters
{
    @Override
    PublicKey readPublicKey(In in) throws IOException
    {
        byte[] modulus = in.readTwoBytesOfBytes();
        byte[] publicExponent = in.readOneByteOfBytes();
        return KeyUtil.rsaPublicKey(modulus, publicExponent);
    }

    @Override
    String checkPublicKey(PublicKey publicKey)
    {
        try
        {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            int bitLen = rsaPublicKey.getModulus().bitLength();
            if (bitLen < 2048)
            {
                return "RSA key too small (" + bitLen + ")";
            }
        }
        catch (ClassCastException e)
        {
            return "Wrong key type (expecting RSA Public Key): " + e;
        }

        return null;
    }

    static class Pkcs15 extends Rsa2048
    {
        @Override
        byte getIdentifier()
        {
            return RSA2048_PKCS1_5;
        }

        @Override
        String javaAlgorithm()
        {
            return "NONEwithRSA";
        }
    }

    static class Pss extends Rsa2048
    {
        @Override
        byte getIdentifier()
        {
            return RSA2048_PSS;
        }

        @Override
        String javaAlgorithm()
        {
            return "NONEwithRSAandMGF1";
        }

    }
}
