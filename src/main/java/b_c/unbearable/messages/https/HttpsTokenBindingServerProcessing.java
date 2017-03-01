package b_c.unbearable.messages.https;

import b_c.unbearable.messages.SignatureResult;
import b_c.unbearable.messages.TokenBinding;
import b_c.unbearable.messages.TokenBindingMessage;

import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 *
 */
public class HttpsTokenBindingServerProcessing
{
    public TlsTbInfo getTbInfo(SSLEngine engine) throws TBException, NoSuchMethodException, IllegalAccessException
    {
        Class<? extends SSLEngine> engineClass = engine.getClass();
        try
        {
            Byte negotiatedKeyParamsId;
            byte[] ekm;
            Method tbKeyParamsMethod = engineClass.getMethod("getTokenBindingKeyParamsId");
            negotiatedKeyParamsId = (Byte)tbKeyParamsMethod.invoke(engine);

            Method ekmMethod = engineClass.getMethod("exportKeyingMaterial", String.class, int.class);
            Object invoked = ekmMethod.invoke(engine, "EXPORTER-Token-Binding", 32);
            ekm = (byte[]) invoked;
            return new TlsTbInfo(negotiatedKeyParamsId, ekm);
        }
        catch (InvocationTargetException e)
        {
            throw new TBException("Exception thrown by an invoked method on SSLEngine.", e.getTargetException());
        }
    }

    public TokenBindingMessage processSecTokenBindingHeader(String encodedTokenBindingMessage, Byte negotiatedTbKeyParams, byte[] ekm)
            throws TBException
    {
        if (negotiatedTbKeyParams == null)
        {
            String msg = "The Token Binding protocol was not negotiated but the client sent a Token Binding message.";
            throw new TBException(msg);
        }

        TokenBindingMessage tokenBindingMessage;
        try
        {
            tokenBindingMessage = TokenBindingMessage.fromBase64urlEncoded(encodedTokenBindingMessage, ekm);
        }
        catch (IOException e)
        {
            String msg = "Unexpected problem processing the Token Binding message.";
            throw new TBException(msg, e);
        }

        TokenBinding providedTokenBinding = tokenBindingMessage.getProvidedTokenBinding();
        if (providedTokenBinding == null)
        {
            throw new TBException("The Token Binding message does not contain a provided_token_binding.");
        }

        SignatureResult signatureResult = providedTokenBinding.getSignatureResult();
        SignatureResult.Status sigStatus = signatureResult.getStatus();
        if (sigStatus != SignatureResult.Status.VALID)
        {
            String msg = String.format("The signature of the provided Token Binding is not valid (%s)", signatureResult);
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
                String msg = String.format("The signature of the referred Token Binding is not valid (%s)", referredSignatureResult);
                throw new TBException(msg);
            }
        }

        return tokenBindingMessage;
    }


    public static class TlsTbInfo
    {
        private Byte negotiatedKeyParamsId;
        private byte[] ekm;

        TlsTbInfo(Byte negotiatedKeyParamsId, byte[] ekm)
        {
            this.negotiatedKeyParamsId = negotiatedKeyParamsId;
            this.ekm = ekm;
        }

        public Byte getNegotiatedKeyParamsId()
        {
            return negotiatedKeyParamsId;
        }

        public byte[] getEkm()
        {
            return ekm;
        }
    }
}
