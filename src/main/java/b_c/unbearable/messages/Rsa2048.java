package b_c.unbearable.messages;

import b_c.unbearable.utils.In;
import b_c.unbearable.utils.KeyUtil;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 *
 */
public abstract class Rsa2048 extends TokenBindingKeyParameters
{
    @Override
    PublicKey readPublicKey(In in, int length) throws IOException
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
        String getJavaAlgorithm()
        {
            return "SHA256withRSA";
        }
    }

    static class Pss extends Rsa2048
    {
        AlgorithmParameterSpec PSS_SPEC = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

        @Override
        byte getIdentifier()
        {
            return RSA2048_PSS;
        }

        @Override
        String getJavaAlgorithm()
        {
            return "SHA256withRSAandMGF1";
        }

        @Override
        AlgorithmParameterSpec getJavaAlgorithmParameterSpec()
        {
            return PSS_SPEC;
        }
    }
}
