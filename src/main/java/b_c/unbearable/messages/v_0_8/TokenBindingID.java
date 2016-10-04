package b_c.unbearable.messages.v_0_8;

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


}
