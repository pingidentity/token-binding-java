package com.pingidentity.oss.unbearable.utils;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 *
 */
public class RsaKeyUtil
{

    public static final String RSA = "RSA";

    public static RSAPublicKey rsaPublicKey(byte[] modulus, byte[] publicExponent) throws GeneralSecurityException
    {
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(Util.bigInt(modulus), Util.bigInt(publicExponent));
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return (RSAPublicKey) kf.generatePublic(rsaPublicKeySpec);
    }

    public static KeyPair generate2048RsaKeyPair() throws GeneralSecurityException
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }


}
