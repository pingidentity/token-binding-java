package b_c.unbearable.utils;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

/**
 *
 */
public class EcKeyUtil
{
    public static final String P256_CURVE_NAME = "secp256r1";
    public static final String EC = "EC";

    public static ECPublicKey p256publicKey(byte[] x, byte[] y) throws GeneralSecurityException
    {
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(EC);
        algorithmParameters.init(new ECGenParameterSpec(P256_CURVE_NAME));
        ECParameterSpec ecParameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(Util.bigInt(x), Util.bigInt(y));
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(point, ecParameterSpec);
        KeyFactory kf = KeyFactory.getInstance(EC);
        return (ECPublicKey) kf.generatePublic(ecPublicKeySpec);
    }

    public static KeyPair generateEcP256KeyPair() throws GeneralSecurityException
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(EC);
        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(EC);
        algorithmParameters.init(new ECGenParameterSpec(P256_CURVE_NAME));
        keyPairGenerator.initialize(new ECGenParameterSpec(P256_CURVE_NAME));
        return  keyPairGenerator.generateKeyPair();
    }
}
