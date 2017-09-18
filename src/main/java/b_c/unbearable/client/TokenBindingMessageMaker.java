package b_c.unbearable.client;

import b_c.unbearable.messages.TokenBindingKeyParameters;
import b_c.unbearable.messages.TokenBindingType;
import b_c.unbearable.utils.Out;
import b_c.unbearable.utils.Util;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class TokenBindingMessageMaker
{
    private byte[] ekm;
    List<TB> tokenBindings = new ArrayList<>();

    public TokenBindingMessageMaker ekm(byte[] ekm)
    {
        this.ekm = ekm;
        return this;
    }

    public TokenBindingMessageMaker providedTokenBinding(byte keyParamsType, KeyPair keyPair)
    {
        return tokenBinding(TokenBindingType.PROVIDED, keyParamsType, keyPair);
    }

    public TokenBindingMessageMaker referredTokenBinding(byte keyParamsType, KeyPair keyPair)
    {
        return tokenBinding(TokenBindingType.REFERRED, keyParamsType, keyPair);
    }

    public TokenBindingMessageMaker tokenBinding(byte tokenBindingType, byte keyParamsType, KeyPair keyPair)
    {
        tokenBindings.add(new TB(tokenBindingType, keyParamsType, keyPair));
        return this;
    }

    public byte[] makeTokenBindingMessage() throws GeneralSecurityException
    {
        Out tokenBindingsOut = new Out(140);
        for (TB tb : tokenBindings)
        {
            TokenBindingKeyParameters tbKeyParams = TokenBindingKeyParameters.fromIdentifier(tb.keyParamsType);
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
            tbOut.putTwoBytesOfBytes(new byte[0]); // empty extensions for now TODO
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

        TB(byte tokenBindingType, byte keyParamsType, KeyPair keyPair)
        {
            this.tokenBindingType = tokenBindingType;
            this.keyParamsType = keyParamsType;
            this.keyPair = keyPair;
        }
    }
}
