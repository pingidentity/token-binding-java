package com.pingidentity.oss.unbearable.server;

import com.pingidentity.oss.unbearable.TokenBindingException;
import com.pingidentity.oss.unbearable.messages.SignatureResult;
import com.pingidentity.oss.unbearable.messages.TokenBinding;
import com.pingidentity.oss.unbearable.messages.TokenBindingMessage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

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

        boolean seenProvided = false;
        boolean seenReferred = false;

        List<TokenBinding> tokenBindings = tokenBindingMessage.getTokenBindings();
        for (TokenBinding tb : tokenBindings)
        {
            if (tb.getTokenBindingType().isProvided())
            {
                if (!seenProvided)
                {
                    seenProvided = true;
                    checkProvided(negotiatedTbKeyParams, ekm, tbmBytes, tb);
                }
                else
                {
                    String msg = String.format("The Token Binding message contains more than one provided_token_binding %s", Arrays.toString(tbmBytes));
                    throw new TokenBindingException(msg);
                }
            }
            else if (tb.getTokenBindingType().isReferred())
            {
                if (!seenReferred)
                {
                    seenReferred = true;
                    checkReferred(ekm, tbmBytes, tb);
                }
                else
                {
                    String msg = String.format("The Token Binding message contains more than one referred_token_binding %s", Arrays.toString(tbmBytes));
                    throw new TokenBindingException(msg);
                }
            }
            else
            {
                checkOther(ekm, tbmBytes, tb);
            }
        }

        if (!seenProvided)
        {
            String msg = String.format("The Token Binding message does not contain a provided_token_binding %s", Arrays.toString(tbmBytes));
            throw new TokenBindingException(msg);
        }

        return tokenBindingMessage;
    }

    private void checkProvided(Byte negotiatedTbKeyParams, byte[] ekm, byte[] tbmBytes, TokenBinding providedTokenBinding) throws TokenBindingException
    {
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
    }

    private void checkReferred(byte[] ekm, byte[] tbmBytes, TokenBinding referredTokenBinding) throws TokenBindingException
    {
        checkSigNotInvalid(ekm, tbmBytes, referredTokenBinding, "referred");
    }

    private void checkOther(byte[] ekm, byte[] tbmBytes, TokenBinding tokenBinding) throws TokenBindingException
    {
        checkSigNotInvalid(ekm, tbmBytes, tokenBinding,  "type=" + tokenBinding.getTokenBindingType().getType());
    }
    
    private void checkSigNotInvalid(byte[] ekm, byte[] tbmBytes, TokenBinding tokenBinding, String name) throws TokenBindingException
    {
        SignatureResult signatureResult = tokenBinding.getSignatureResult();
        SignatureResult.Status signatureStatus = signatureResult.getStatus();
        if (signatureStatus == SignatureResult.Status.INVALID)
        {
            String msg = String.format("The signature of the %s Token Binding is invalid (%s) Token Binding message %s EKM %s ",
                    name, signatureResult, Arrays.toString(tbmBytes), Arrays.toString(ekm));
            throw new TokenBindingException(msg);
        }
    }
}
