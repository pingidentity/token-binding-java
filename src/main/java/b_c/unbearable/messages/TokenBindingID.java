package b_c.unbearable.messages;

import java.security.PublicKey;

/**
 *
 */
public class TokenBindingID
{
    /**
     * Token Binding protocol
     * implementations SHOULD make Token Binding IDs available to the
     * application as opaque byte sequences.  E.g. server applications will
     * use Token Binding IDs when generating and verifying bound tokens.
     */
    byte[] rawTokenBindingID;

    TokenBindingKeyParameters tokenBindingKeyParameters;

    PublicKey publicKey;

    public byte[] getRawTokenBindingID()
    {
        return rawTokenBindingID;
    }

    public TokenBindingKeyParameters getTokenBindingKeyParameters()
    {
        return tokenBindingKeyParameters;
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }
}
