package com.pingidentity.oss.unbearable.client;

import com.pingidentity.oss.unbearable.messages.TokenBindingKeyParameters;
import com.pingidentity.oss.unbearable.messages.TokenBindingType;
import com.pingidentity.oss.unbearable.utils.Out;
import com.pingidentity.oss.unbearable.utils.Util;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 *
 */
public class TokenBindingMessageMaker
{
    private static final byte[] NO_EXTENSIONS = new byte[0];

    private byte[] ekm;
    List<TB> tokenBindings = new ArrayList<>();

    public TokenBindingMessageMaker ekm(byte[] ekm)
    {
        this.ekm = ekm;
        return this;
    }

    public TokenBindingMessageMaker providedTokenBinding(byte keyParamsType, KeyPair keyPair)
    {
        return tokenBinding(TokenBindingType.PROVIDED, keyParamsType, keyPair, NO_EXTENSIONS);
    }

    public TokenBindingMessageMaker referredTokenBinding(byte keyParamsType, KeyPair keyPair)
    {
        return tokenBinding(TokenBindingType.REFERRED, keyParamsType, keyPair, NO_EXTENSIONS);
    }

    public TokenBindingMessageMaker tokenBinding(byte tokenBindingType, byte keyParamsType, KeyPair keyPair, byte[] extensions)
    {
        tokenBindings.add(new TB(tokenBindingType, keyParamsType, keyPair, extensions));
        return this;
    }

    public String makeEncodedTokenBindingMessage() throws GeneralSecurityException
    {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(makeTokenBindingMessage());
    }

    public byte[] makeTokenBindingMessage() throws GeneralSecurityException
    {
        Out tokenBindingsOut = new Out(140);
        for (TB tb : tokenBindings)
        {
            TokenBindingKeyParameters tbKeyParams = TokenBindingKeyParameters.fromIdentifier(tb.keyParamsType);
            if (ekm == null)
            {
                throw new IllegalArgumentException("An EKM was not provided");
            }
            final byte[] signatureInput = Util.signatureInput(tb.tokenBindingType, tb.keyParamsType, ekm);
            final byte[] signature = tbKeyParams.sign(signatureInput, tb.keyPair.getPrivate());
            byte[] tokenBindingPublicKey = tbKeyParams.encodeTokenBindingPublicKey(tb.keyPair.getPublic());
            Out tbidOut = new Out(tokenBindingPublicKey.length + 3);
            tbidOut.putOneByteInt(Util.intFromByte(tb.keyParamsType));
            tbidOut.putTwoBytesOfBytes(tokenBindingPublicKey);
            byte[] tokenBindingId = tbidOut.toByteArray();

            Out tbOut = new Out(tokenBindingId.length + signature.length + 5);
            tbOut.putOneByteInt(Util.intFromByte(tb.tokenBindingType));
            tbOut.write(tokenBindingId);
            tbOut.putTwoBytesOfBytes(signature);
            tbOut.putTwoBytesOfBytes(tb.extensions);
            byte[] tokenBinding = tbOut.toByteArray();
            tokenBindingsOut.write(tokenBinding);
        }

        final byte[] bindingsBytes = tokenBindingsOut.toByteArray();
        Out messageOut = new Out(bindingsBytes.length + 2);
        messageOut.putTwoBytesOfBytes(bindingsBytes);

        return messageOut.toByteArray();
    }

    private class TB
    {
        byte tokenBindingType;
        byte keyParamsType;
        KeyPair keyPair;
        byte[] extensions;

        TB(byte tokenBindingType, byte keyParamsType, KeyPair keyPair, byte[] extensions)
        {
            this.tokenBindingType = tokenBindingType;
            this.keyParamsType = keyParamsType;
            this.keyPair = keyPair;
            this.extensions = extensions;
        }
    }
}
