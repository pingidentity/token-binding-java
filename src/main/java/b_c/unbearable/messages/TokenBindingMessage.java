package b_c.unbearable.messages;

import b_c.unbearable.messages.utils.In;
import b_c.unbearable.messages.utils.Util;

import java.io.ByteArrayOutputStream;
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

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(tb.tokenBindingType.getType());
            baos.write(tb.tokenBindingID.tokenBindingKeyParameters.getIdentifier());
            baos.write(ekm);
            byte[] signatureInput = baos.toByteArray();
            tb.signatureResult = keyParams.evaluateSignature(signatureInput, tb.signature, tb.tokenBindingID.publicKey);

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