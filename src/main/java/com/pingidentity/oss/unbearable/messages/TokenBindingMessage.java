package com.pingidentity.oss.unbearable.messages;

import com.pingidentity.oss.unbearable.utils.In;
import com.pingidentity.oss.unbearable.utils.Util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
public class TokenBindingMessage
{
    private List<TokenBinding> tokenBindings = new ArrayList<>();

    public static TokenBindingMessage fromBytes(byte[] tokenBindingMessageBytes, byte[] ekm) throws IOException, GeneralSecurityException
    {
        In in = new In(tokenBindingMessageBytes);
        int len = in.readTwoByteInt();
        if (len != in.available())
        {
            throw new IOException("TokenBindingMessage length of " + len + " indicated but " + in.available() + " bytes are available " + Arrays.toString(tokenBindingMessageBytes) );
        }

        TokenBindingMessage tokenBindingMessage = new TokenBindingMessage();

        while (in.available() > 0)
        {
            TokenBinding tb = new TokenBinding();

            final int tbTypeAsInt = in.readOneByteInt();
            final byte tbType = Util.byteFromInt(tbTypeAsInt);
            tb.tokenBindingType = new TokenBindingType(tbType);

            in.mark();
            int keyParametersIdentifierAsInt = in.readOneByteInt();
            byte keyParamsIdentifier = Util.byteFromInt(keyParametersIdentifierAsInt);
            TokenBindingKeyParameters keyParams = TokenBindingKeyParameters.fromIdentifier(keyParamsIdentifier);
            tb.tokenBindingID = new TokenBindingID();
            tb.tokenBindingID.tokenBindingKeyParameters = keyParams;
            int keyLength = in.readTwoByteInt();
            tb.tokenBindingID.publicKey = keyParams.readPublicKey(in, keyLength);
            tb.tokenBindingID.rawTokenBindingID = in.readBytesFromMark();

            tb.signature = in.readTwoBytesOfBytes();
            tb.extensions = in.readTwoBytesOfBytes();

            byte[] signatureInput = Util.signatureInput(tb.tokenBindingType.getType(), tb.tokenBindingID.tokenBindingKeyParameters.getIdentifier(), ekm);
            tb.signatureResult = keyParams.evaluateSignature(signatureInput, tb.signature, tb.tokenBindingID.publicKey);

            tokenBindingMessage.tokenBindings.add(tb);
        }

        if (tokenBindingMessage.getTokenBindings().isEmpty())
        {
            throw new IOException("No TokenBinding structure in the Token Binding message but there must be at least one.");
        }

        return tokenBindingMessage;
    }

    public TokenBinding getProvidedTokenBinding()
    {
        return getTokenBindingByType(TokenBindingType.PROVIDED);
    }

    public TokenBinding getReferredTokenBinding()
    {
        return getTokenBindingByType(TokenBindingType.REFERRED);
    }

    public TokenBinding getTokenBindingByType(int type)
    {
        for (TokenBinding tb : tokenBindings)
        {
            if (tb.tokenBindingType.getType() == type)
            {
                return tb;
            }
        }

        return null;
    }

    public List<TokenBinding> getTokenBindings()
    {
        return tokenBindings;
    }
}