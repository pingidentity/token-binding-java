package b_c.unbearable.utils;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 *
 */
public class RsaKeyUtil
{

    public static final String RSA = "RSA";

    public static RSAPublicKey rsaPublicKey(byte[] modulus, byte[] publicExponent)
    {
        try
        {
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(Util.bigInt(modulus), Util.bigInt(publicExponent));
            KeyFactory kf = KeyFactory.getInstance(RSA);
            return (RSAPublicKey) kf.generatePublic(rsaPublicKeySpec);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            throw new RuntimeException("Unable to create RSAPublicKey object from modulus & public exponent byte arrays", e);// TODO type
        }
    }

    public static KeyPair generate2048RsaKeyPair() throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }


}
