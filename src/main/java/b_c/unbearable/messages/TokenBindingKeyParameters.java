package b_c.unbearable.messages;

import b_c.unbearable.messages.utils.ExceptionUtil;
import b_c.unbearable.messages.utils.In;
import b_c.unbearable.messages.utils.Util;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 *
 */
public abstract class TokenBindingKeyParameters
{
    public static final byte RSA2048_PKCS1_5 = 0;
    public static final byte RSA2048_PSS = 1;
    public static final byte ECDSAP256 = 2;

    static TokenBindingKeyParameters fromIdentifier(byte identifier) throws IOException
    {
        switch (identifier)
        {
            case ECDSAP256:
                return new EcdsaP256();
            case RSA2048_PKCS1_5:
                return new Rsa2048.Pkcs15();
            case RSA2048_PSS:
                return new Rsa2048.Pss();
            default:
                throw new IOException("Unknown TokenBindingKeyParameters value: " + Util.intFromByte(identifier));

        }
    }

    abstract byte getIdentifier();

    abstract PublicKey readPublicKey(In in) throws IOException;

    abstract String javaAlgorithm();

    abstract String checkPublicKey(PublicKey publicKey);

    SignatureResult evaluateSignature(byte[] ekm, byte[] signature, PublicKey publicKey) throws IOException
    {
        String keyProblem = checkPublicKey(publicKey);
        if (keyProblem != null)
        {
            SignatureResult signatureResult = new SignatureResult(SignatureResult.Status.INVALID);
            signatureResult.addComment("Unacceptable public key in TokenBindingID: " + keyProblem);
            return signatureResult;
        }

        Signature verifier;
        try
        {
            verifier = Signature.getInstance(javaAlgorithm());
        }
        catch (NoSuchAlgorithmException e)
        {
            SignatureResult signatureResult = new SignatureResult(SignatureResult.Status.UNEVALUATED);
            signatureResult.addComment("Unsupported TokenBindingKeyParameters type: " + ExceptionUtil.toStringWithCauses(e));
            return signatureResult;
        }

        try
        {
            verifier.initVerify(publicKey);
            verifier.update(ekm);
            boolean legit = verifier.verify(signature);
            return legit ? SignatureResult.VALID : SignatureResult.INVALID;
        }
        catch (InvalidKeyException | SignatureException e)
        {
            SignatureResult signatureResult = new SignatureResult(SignatureResult.Status.INVALID);
            signatureResult.addComment("Problem encountered during verification: " + ExceptionUtil.toStringWithCauses(e));
            return signatureResult;
        }

    }



}
