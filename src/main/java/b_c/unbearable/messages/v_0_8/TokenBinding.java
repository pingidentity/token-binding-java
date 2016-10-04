package b_c.unbearable.messages.v_0_8;

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

    public byte getKeyParamsIdentifier()
    {
        return tokenBindingID.tokenBindingKeyParameters.getIdentifier();
    }
}
