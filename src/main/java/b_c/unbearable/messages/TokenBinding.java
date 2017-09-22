package b_c.unbearable.messages;

/**
 *
 */
public class TokenBinding
{
    TokenBindingType tokenBindingType;
    TokenBindingID tokenBindingID;
    byte[] signature;
    byte[] extensions;

    SignatureResult signatureResult;

    public SignatureResult getSignatureResult()
    {
        return signatureResult;
    }

    public byte[] getOpaqueTokenBindingID()
    {
        return tokenBindingID.rawTokenBindingID;
    }

    public TokenBindingID getTokenBindingID()
    {
        return tokenBindingID;
    }

    public byte getKeyParamsIdentifier()
    {
        return tokenBindingID.tokenBindingKeyParameters.getIdentifier();
    }

    public byte[] getExtensions()
    {
        return extensions;
    }

    public byte[] getSignature()
    {
        return signature;
    }
}
