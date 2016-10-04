package b_c.unbearable.messages.v_0_8;

import b_c.unbearable.messages.utils.In;
import b_c.unbearable.messages.utils.Util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 *
 */
public class TokenBindingMessage
{
    private List<TokenBinding> tokenBindings = new ArrayList<>();

    public static TokenBindingMessage fromBase64urlEncoded(String encodedTokenBindingMessage, byte[] ekm) throws IOException
    {
        byte[] tokenBindingMessageBytes = Base64.getUrlDecoder().decode(encodedTokenBindingMessage);
        return fromBytes(tokenBindingMessageBytes, ekm);
    }

    public static TokenBindingMessage fromBytes(byte[] tokenBindingMessageBytes, byte[] ekm) throws IOException
    {
        In in = new In(tokenBindingMessageBytes);
        int len = in.readTwoByteInt();
        if (len != in.available())
        {
            throw new IOException("TokenBindingMessage length of " + len + " indicated but only " + in.available() + " bytes are available.");
        }

        TokenBindingMessage tokenBindingMessage = new TokenBindingMessage();

        while (in.available() > 0)
        {
            TokenBinding tb = new TokenBinding();

            final int type = in.readOneByteInt();
            tb.tokenBindingType = new TokenBindingType(type);

            in.mark();
            int keyParametersIdentifier = in.readOneByteInt();
            TokenBindingKeyParameters keyParams = TokenBindingKeyParameters.fromIdentifier(Util.byteFromInt(keyParametersIdentifier));
            tb.tokenBindingID = new TokenBindingID();
            tb.tokenBindingID.tokenBindingKeyParameters = keyParams;
            tb.tokenBindingID.publicKey = keyParams.readPublicKey(in);
            tb.tokenBindingID.rawTokenBindingID = in.readBytesFromMark();

            tb.signature = in.readTwoBytesOfBytes();
            tb.extensions = in.readTwoBytesOfBytes();

            tb.signatureResult = tb.tokenBindingID.tokenBindingKeyParameters.evaluateSignature(ekm, tb.signature, tb.tokenBindingID.publicKey);

            tokenBindingMessage.tokenBindings.add(tb);
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

    TokenBinding getTokenBindingByType(int type)
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