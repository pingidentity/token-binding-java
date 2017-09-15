package b_c.unbearable.utils;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 *
 */
public class KeyUtil
{

    static final int SIGNUM_POSITIVE = 1;

    public static ECPublicKey p256publicKey(byte[] x, byte[] y)
    {
        try
        {
            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
            algorithmParameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecParameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);
            ECPoint point = new ECPoint(bigInt(x), bigInt(y));
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(point, ecParameterSpec);
            KeyFactory kf = KeyFactory.getInstance("EC");
            return (ECPublicKey) kf.generatePublic(ecPublicKeySpec);
        }
        catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidKeySpecException e)
        {
            throw new RuntimeException("Unable to create ECPublicKey object from x & y byte arrays", e);
        }
    }


    public static RSAPublicKey rsaPublicKey(byte[] modulus, byte[] publicExponent)
    {
        try
        {
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(bigInt(modulus), bigInt(publicExponent));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(rsaPublicKeySpec);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            throw new RuntimeException("Unable to create RSAPublicKey object from modulus & public exponent byte arrays", e);
        }
    }

    private static BigInteger bigInt(byte[] magnitude)
    {
        return new BigInteger(SIGNUM_POSITIVE, magnitude);
    }

}
