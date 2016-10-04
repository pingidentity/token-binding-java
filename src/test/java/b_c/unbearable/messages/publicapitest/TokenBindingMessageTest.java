package b_c.unbearable.messages.publicapitest;

import b_c.unbearable.messages.SignatureResult;
import b_c.unbearable.messages.TokenBinding;
import b_c.unbearable.messages.TokenBindingKeyParameters;
import b_c.unbearable.messages.TokenBindingMessage;
import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 *
 */
public class TokenBindingMessageTest
{

    @Test
    public void v0_10_singleProvidedECDSAP256() throws IOException
    {
        String encoded = "AIkAAgBBQLlO7EVk3V2g3-zmgRpq2qKfbw6F1rZ97Y15siYmjuy3U5CKNcwXnrHYqM87PcilegJ7Ooxd7KpiRGRIp" +
                "5jCAXoAQCLhZIeSUTWv3ETKb9qPDyWzxmQlwFDFkmeGSophCtEEdfOnsKotZNOgQ3Fz3DIwHZb-GqdkjoHiVN_hAE5dG-gAAA";

        byte[] ekm = new byte[] {-25, 60, -5, -91, -81, 127, -84, -127, -124, -17, -42, 106, -11, -15, 20, -98, 95,
                -110, 108, -80, -91, -86, 77, 74, -11, -74, -84, -10, 21, -103, -5, -4};

        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBase64urlEncoded(encoded, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));

        assertNull(tokenBindingMessage.getReferredTokenBinding());

        // now change the ekm and make sure it parses but has an invalid signature
        ekm[0] = 77;
        tokenBindingMessage = TokenBindingMessage.fromBase64urlEncoded(encoded, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.INVALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        assertNotNull(provided.getOpaqueTokenBindingID());
        assertNull(tokenBindingMessage.getReferredTokenBinding());
    }

    @Test
    public void v0_10_simpleUnknownKeyParamType() throws IOException
    {
        byte unknownType = 88;
        byte[] tbmsg =
                {0, -119, 0, unknownType, 0, 65, 64, -71, 78, -20, 69, 100, -35, 93, -96, -33, -20, -26, -127, 26, 106, -38, -94, -97, 111,
                14, -123, -42, -74, 125, -19, -115, 121, -78, 38, 38, -114, -20, -73, 83, -112, -118, 53, -52, 23, -98, -79, -40, -88,
                -49, 59, 61, -56, -91, 122, 2, 123, 58, -116, 93, -20, -86, 98, 68, 100, 72, -89, -104, -62, 1, 122, 0, 64, 34, -31, 100,
                -121, -110, 81, 53, -81, -36, 68, -54, 111, -38, -113, 15, 37, -77, -58, 100, 37, -64, 80, -59, -110, 103, -122, 74, -118,
                97, 10, -47, 4, 117, -13, -89, -80, -86, 45, 100, -45, -96, 67, 113, 115, -36, 50, 48, 29, -106, -2, 26, -89, 100, -114,
                -127, -30, 84, -33, -31, 0, 78, 93, 27, -24, 0, 0};

        byte[] ekm = new byte[] {-25, 60, -5, -91, -81, 127, -84, -127, -124, -17, -42, 106, -11, -15, 20, -98, 95,
                -110, 108, -80, -91, -86, 77, 74, -11, -74, -84, -10, 21, -103, -5, -4};

        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBytes(tbmsg, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.UNEVALUATED, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(unknownType, equalTo(provided.getKeyParamsIdentifier()));
        String msg = provided.getSignatureResult().getCommentary().iterator().next();
        assertThat(msg, containsString(String.valueOf(unknownType)));
        assertNull(tokenBindingMessage.getReferredTokenBinding());
    }
}
