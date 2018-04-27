package com.pingidentity.oss.unbearable.server;

import com.pingidentity.oss.unbearable.TokenBindingException;
import com.pingidentity.oss.unbearable.messages.SignatureResult;
import com.pingidentity.oss.unbearable.messages.TokenBinding;
import com.pingidentity.oss.unbearable.messages.TokenBindingMessage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

/**
 *
 */
public class HttpsTokenBindingServerProcessing
{
    public TokenBindingMessage processSecTokenBindingHeader(String encodedTokenBindingMessage, Byte negotiatedTbKeyParams, byte[] ekm)
            throws TokenBindingException
    {
        if (encodedTokenBindingMessage == null)
        {
            return null;
        }

        if (negotiatedTbKeyParams == null)
        {
            String msg = "The Token Binding protocol was not negotiated but the client sent a Token Binding message.";
            throw new TokenBindingException(msg);
        }

        byte[] tbmBytes = Base64.getUrlDecoder().decode(encodedTokenBindingMessage);

        TokenBindingMessage tokenBindingMessage;
        try
        {
            tokenBindingMessage = TokenBindingMessage.fromBytes(tbmBytes, ekm);
        }
        catch (IOException | GeneralSecurityException e)
        {
            String msg = String.format("Unexpected problem processing the Token Binding message %s: %s", Arrays.toString(tbmBytes), e);
            throw new TokenBindingException(msg, e);
        }

        // TODO new in https://www.ietf.org/rfcdiff?url2=draft-ietf-tokbind-https-12 has "exactly one" for provided and referred, which isn't checked now

        TokenBinding providedTokenBinding = tokenBindingMessage.getProvidedTokenBinding();
        if (providedTokenBinding == null)
        {
            String msg = String.format("The Token Binding message does not contain a provided_token_binding %s", Arrays.toString(tbmBytes));
            throw new TokenBindingException(msg);
        }

        SignatureResult signatureResult = providedTokenBinding.getSignatureResult();
        SignatureResult.Status sigStatus = signatureResult.getStatus();
        if (sigStatus != SignatureResult.Status.VALID)
        {
            String msg = String.format("The signature of the provided Token Binding is not valid (%s) Token Binding message %s EKM %s",
                    signatureResult, Arrays.toString(tbmBytes), Arrays.toString(ekm));
            throw new TokenBindingException(msg);
        }

        byte kpId = providedTokenBinding.getKeyParamsIdentifier();
        if (negotiatedTbKeyParams != kpId)
        {
            String msg = String.format("The key parameters of provided_token_binding %s is different than negotiated %s.", kpId, negotiatedTbKeyParams);
            throw new TokenBindingException(msg);
        }

        TokenBinding referredTokenBinding = tokenBindingMessage.getReferredTokenBinding();
        if (referredTokenBinding != null)
        {
            SignatureResult referredSignatureResult = referredTokenBinding.getSignatureResult();
            SignatureResult.Status referredSigStatus = referredSignatureResult.getStatus();
            if (referredSigStatus == SignatureResult.Status.INVALID)
            {
                String msg = String.format("The signature of the referred Token Binding is not valid (%s) Token Binding message %s EKM %s ",
                        referredSignatureResult, Arrays.toString(tbmBytes), Arrays.toString(ekm));
                throw new TokenBindingException(msg);
            }
        }

        // TODO other types to be treated similar to referred...

        return tokenBindingMessage;
    }
}
