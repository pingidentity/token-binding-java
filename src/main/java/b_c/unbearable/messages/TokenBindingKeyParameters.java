package b_c.unbearable.messages;

import b_c.unbearable.utils.ExceptionUtil;
import b_c.unbearable.utils.In;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

/**
 *
 */
public abstract class TokenBindingKeyParameters
{
    public static final byte RSA2048_PKCS1_5 = 0;
    public static final byte RSA2048_PSS = 1;
    public static final byte ECDSAP256 = 2;

    // TODO some kind of check if available

    public static TokenBindingKeyParameters fromIdentifier(byte identifier)
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
                return new UnknownKeyParameters(identifier);
        }
    }

    abstract byte getIdentifier();

    abstract PublicKey readPublicKey(In in, int length) throws IOException;

    public abstract byte[] encodeTokenBindingPublicKey(PublicKey publicKey);

    abstract String getJavaAlgorithm();

    abstract String checkPublicKey(PublicKey publicKey);

    AlgorithmParameterSpec getJavaAlgorithmParameterSpec()
    {
        return null;
    }

    SignatureResult evaluateSignature(byte[] signatureInput, byte[] signature, PublicKey publicKey) throws IOException
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
            verifier = Signature.getInstance(getJavaAlgorithm());
            AlgorithmParameterSpec algorithmParameterSpec = getJavaAlgorithmParameterSpec();
            if (algorithmParameterSpec != null)
            {
                verifier.setParameter(algorithmParameterSpec);
            }
        }
        catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e)
        {
            SignatureResult signatureResult = new SignatureResult(SignatureResult.Status.UNEVALUATED);
            signatureResult.addComment("Unsupported TokenBindingKeyParameters type ( " + getIdentifier() + "):" + ExceptionUtil.toStringWithCauses(e));
            return signatureResult;
        }

        try
        {
            verifier.initVerify(publicKey);
            verifier.update(signatureInput);
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

    public byte[] sign(byte[] signatureInput, PrivateKey privateKey) throws GeneralSecurityException
    {
        Signature signer = Signature.getInstance(getJavaAlgorithm());
        AlgorithmParameterSpec algorithmParameterSpec = getJavaAlgorithmParameterSpec();
        if (algorithmParameterSpec != null)
        {
            signer.setParameter(algorithmParameterSpec);
        }

        signer.initSign(privateKey);
        signer.update(signatureInput);
        return signer.sign();
    }


    static class UnknownKeyParameters extends TokenBindingKeyParameters
    {
        UnknownKeyParameters(byte identifier)
        {
            this.identifier = identifier;
        }

        byte identifier;

        @Override
        byte getIdentifier()
        {
            return identifier;
        }

        @Override
        PublicKey readPublicKey(In in, int length) throws IOException
        {
            for (int i = 0; i < length; i++)
            {
                in.read();
            }
            return null;
        }

        @Override
        public byte[] encodeTokenBindingPublicKey(PublicKey publicKey)
        {
            return new byte[0];
        }

        @Override
        String getJavaAlgorithm()
        {
            return "UNKNOWN";
        }

        @Override
        String checkPublicKey(PublicKey publicKey)
        {
            return null;
        }

        @Override
        SignatureResult evaluateSignature(byte[] signatureInput, byte[] signature, PublicKey publicKey) throws IOException
        {
            SignatureResult signatureResult = new SignatureResult(SignatureResult.Status.UNEVALUATED);
            signatureResult.addComment("Unknown Token Binding Key Parameters type: " + getIdentifier());
            return signatureResult;
        }

        @Override
        public byte[] sign(byte[] signatureInput, PrivateKey privateKey) throws GeneralSecurityException
        {
            throw new GeneralSecurityException("Cannot sign with unknown Token Binding Key Parameters type: " + getIdentifier());
        }
    }
}
