package b_c.unbearable.messages.v_0_8;

import b_c.unbearable.messages.utils.In;
import b_c.unbearable.messages.utils.KeyUtil;
import b_c.unbearable.messages.utils.Util;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;


/**
 *
 */
public class EcdsaP256 extends TokenBindingKeyParameters
{
    @Override
    PublicKey readPublicKey(In in) throws IOException
    {
        byte[] point = in.readOneByteOfBytes();
        byte[] x = Util.leftHalf(point);
        byte[] y = Util.rightHalf(point);
        return KeyUtil.p256publicKey(x, y);
    }

    @Override
    String javaAlgorithm()
    {
        return "NONEwithECDSA";
    }

    @Override
    byte getIdentifier()
    {
        return ECDSAP256;
    }

    @Override
    SignatureResult evaluateSignature(byte[] ekm, byte[] signature, PublicKey publicKey) throws IOException
    {
        byte[] convertedSignature = convertConcatenatedToDer(signature);
        return super.evaluateSignature(ekm, convertedSignature, publicKey);
    }

    @Override
    String checkPublicKey(PublicKey publicKey)
    {
        try
        {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            ecPublicKey.getParams().getCurve();
        }
        catch (ClassCastException e)
        {
            return "Wrong key type (expecting EC Public Key): " + e;
        }
        return null;
    }

    /**
     * Convert the concatenation of R and S into DER encoding
     *
     * The result of an ECDSA signature is the EC point (R, S), where R and S are unsigned (very large) integers.
     *
     * The JCA ECDSA signature implementation (sun.security.ec.ECDSASignature) produces and expects a DER encoding
     * of R and S while Token Binding's ECDSAP256 wants R and S as a concatenated byte array.
     * JOSE/JWS treats ECDSA similarly and this  methods that convert to DER from concatenated
     * R and S were taken from jose4j, which were originally derived from the Apache Santuario XML Security library's
     * SignatureECDSA implementation.
     */
    private static byte[] convertConcatenatedToDer(byte[] concatenatedSignatureBytes) throws IOException
    {
        int rawLen = concatenatedSignatureBytes.length/2;

        int i;

        for (i = rawLen; (i > 0) && (concatenatedSignatureBytes[rawLen - i] == 0); i--);

        int j = i;

        if (concatenatedSignatureBytes[rawLen - i] < 0)
        {
            j += 1;
        }

        int k;

        for (k = rawLen; (k > 0) && (concatenatedSignatureBytes[2*rawLen - k] == 0); k--);

        int l = k;

        if (concatenatedSignatureBytes[2*rawLen - k] < 0)
        {
            l += 1;
        }

        int len = 2 + j + 2 + l;
        if (len > 255)
        {
            throw new IOException("Invalid format of ECDSA signature");
        }
        int offset;
        byte derEncodedSignatureBytes[];
        if (len < 128)
        {
            derEncodedSignatureBytes = new byte[2 + 2 + j + 2 + l];
            offset = 1;
        }
        else
        {
            derEncodedSignatureBytes = new byte[3 + 2 + j + 2 + l];
            derEncodedSignatureBytes[1] = (byte) 0x81;
            offset = 2;
        }

        derEncodedSignatureBytes[0] = 48;
        derEncodedSignatureBytes[offset++] = (byte) len;
        derEncodedSignatureBytes[offset++] = 2;
        derEncodedSignatureBytes[offset++] = (byte) j;

        System.arraycopy(concatenatedSignatureBytes, rawLen - i, derEncodedSignatureBytes, (offset + j) - i, i);

        offset += j;

        derEncodedSignatureBytes[offset++] = 2;
        derEncodedSignatureBytes[offset++] = (byte) l;

        System.arraycopy(concatenatedSignatureBytes, 2*rawLen - k, derEncodedSignatureBytes, (offset + l) - k, k);

        return derEncodedSignatureBytes;
    }

    /**
     * Convert the DER encoding of R and S into a concatenation of R and S
     *
     * The result of an ECDSA signature is the EC point (R, S), where R and S are unsigned (very large) integers.
     *
     * The JCA ECDSA signature implementation (sun.security.ec.ECDSASignature) produces and expects a DER encoding
     * of R and S while Token Binding's ECDSAP256 wants R and S as a concatenated byte array.
     * JOSE/JWS treats ECDSA similarly and this method that converts from DER to concatenated
     * R and S were taken from jose4j, which were originally derived from the Apache Santuario XML Security library's
     * SignatureECDSA implementation.
     */
    private static byte[] convertDerToConcatenated(byte derEncodedBytes[], int outputLength) throws IOException
    {

        if (derEncodedBytes.length < 8 || derEncodedBytes[0] != 48)
        {
            throw new IOException("Invalid format of ECDSA signature");
        }

        int offset;
        if (derEncodedBytes[1] > 0)
        {
            offset = 2;
        }
        else if (derEncodedBytes[1] == (byte) 0x81)
        {
            offset = 3;
        }
        else
        {
            throw new IOException("Invalid format of ECDSA signature");
        }

        byte rLength = derEncodedBytes[offset + 1];

        int i;
        for (i = rLength; (i > 0) && (derEncodedBytes[(offset + 2 + rLength) - i] == 0); i--);

        byte sLength = derEncodedBytes[offset + 2 + rLength + 1];

        int j;
        for (j = sLength; (j > 0) && (derEncodedBytes[(offset + 2 + rLength + 2 + sLength) - j] == 0); j--);

        int rawLen = Math.max(i, j);
        rawLen = Math.max(rawLen, outputLength/2);

        if ((derEncodedBytes[offset - 1] & 0xff) != derEncodedBytes.length - offset
                || (derEncodedBytes[offset - 1] & 0xff) != 2 + rLength + 2 + sLength
                || derEncodedBytes[offset] != 2
                || derEncodedBytes[offset + 2 + rLength] != 2)
        {
            throw new IOException("Invalid format of ECDSA signature");
        }

        byte concatenatedSignatureBytes[] = new byte[2*rawLen];

        System.arraycopy(derEncodedBytes, (offset + 2 + rLength) - i, concatenatedSignatureBytes, rawLen - i, i);
        System.arraycopy(derEncodedBytes, (offset + 2 + rLength + 2 + sLength) - j, concatenatedSignatureBytes, 2*rawLen - j, j);

        return concatenatedSignatureBytes;
    }
}
