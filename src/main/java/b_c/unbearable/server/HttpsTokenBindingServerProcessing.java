package b_c.unbearable.server;

import b_c.unbearable.messages.SignatureResult;
import b_c.unbearable.messages.TokenBinding;
import b_c.unbearable.messages.TokenBindingMessage;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

/**
 *
 */
public class HttpsTokenBindingServerProcessing
{
    public TokenBindingMessage processSecTokenBindingHeader(String encodedTokenBindingMessage, Byte negotiatedTbKeyParams, byte[] ekm)
            throws TBException
    {
        if (negotiatedTbKeyParams == null)
        {
            String msg = "The Token Binding protocol was not negotiated but the client sent a Token Binding message.";
            throw new TBException(msg);
        }

        byte[] tbmBytes = Base64.getUrlDecoder().decode(encodedTokenBindingMessage);

        TokenBindingMessage tokenBindingMessage;
        try
        {
            tokenBindingMessage = TokenBindingMessage.fromBytes(tbmBytes, ekm);
        }
        catch (IOException e)
        {
            String msg = String.format("Unexpected problem processing the Token Binding message %s: %s", bts(tbmBytes), e);
            throw new TBException(msg, e);
        }

        TokenBinding providedTokenBinding = tokenBindingMessage.getProvidedTokenBinding();
        if (providedTokenBinding == null)
        {
            String msg = String.format("The Token Binding message does not contain a provided_token_binding %s", bts(tbmBytes));
            throw new TBException(msg);
        }

        SignatureResult signatureResult = providedTokenBinding.getSignatureResult();
        SignatureResult.Status sigStatus = signatureResult.getStatus();
        if (sigStatus != SignatureResult.Status.VALID)
        {
            String msg = String.format("The signature of the provided Token Binding is not valid (%s) Token Binding message %s EKM %s",
                    signatureResult, bts(tbmBytes), bts(ekm));
            throw new TBException(msg);
        }

        byte kpId = providedTokenBinding.getKeyParamsIdentifier();
        if (negotiatedTbKeyParams != kpId)
        {
            String msg = String.format("The key parameters of provided_token_binding %s is different than negotiated %s.", kpId, negotiatedTbKeyParams);
            throw new TBException(msg);
        }

        TokenBinding referredTokenBinding = tokenBindingMessage.getReferredTokenBinding();
        if (referredTokenBinding != null)
        {
            SignatureResult referredSignatureResult = referredTokenBinding.getSignatureResult();
            SignatureResult.Status referredSigStatus = referredSignatureResult.getStatus();
            if (referredSigStatus != SignatureResult.Status.VALID)  // maybe allow unknown todo
            {
                String msg = String.format("The signature of the referred Token Binding is not valid (%s) Token Binding message %s EKM %s ",
                        referredSignatureResult, bts(tbmBytes), bts(ekm));
                throw new TBException(msg);
            }
        }

        return tokenBindingMessage;
    }

    private static String bts(byte[] bytes)
    {
        return Arrays.toString(bytes);
    }

}
