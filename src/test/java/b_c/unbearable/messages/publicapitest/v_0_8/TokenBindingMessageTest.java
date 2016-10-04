package b_c.unbearable.messages.publicapitest.v_0_8;

import b_c.unbearable.messages.v_0_8.SignatureResult;
import b_c.unbearable.messages.v_0_8.TokenBinding;
import b_c.unbearable.messages.v_0_8.TokenBindingKeyParameters;
import b_c.unbearable.messages.v_0_8.TokenBindingMessage;
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
    public void v0_8_singleProvidedECDSAP256() throws IOException
    {
        String encoded = "AIcAAkAgSeZjyyTPGGdPnwDuhIevp1elD4KpiDkE0khlHOahu0n0AmOj-GQ8P9xi4zno7ocIxQcN-GcukkI42J6CVTRx" +
                "AECNjCiTbxChz4TfWWG9s_PPeKevSACmwc_wGClVAlAJB_6Fb0QekjVFxgOqK6hbQcVP188BTYhyKdR9GPmuEli-AAA";

        byte[] ekm = new byte[] {-5, 106, 16, 126, 68, -123, 18, -12, -30, 13, 10, -47, 1, 7, -68, 125, 102, -116, -29,
                -48, -87, -61, -104, 18, -96, -91, 86, 101, 35, -122, -32, -90};


        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBase64urlEncoded(encoded, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());

        // now change the ekm and make sure it parses but has an invalid signature
        ekm[0] = 0;
        tokenBindingMessage = TokenBindingMessage.fromBase64urlEncoded(encoded, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.INVALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        assertNotNull(provided.getOpaqueTokenBindingID());
        assertNull(tokenBindingMessage.getReferredTokenBinding());
    }

    @Test
    public void v0_8_providedAndReferredECDSAP256() throws IOException
    {
        String encoded = "AQ4AAkC5TuxFZN1doN_s5oEaatqin28Ohda2fe2NebImJo7st1OQijXMF56x2KjPOz3IpXoCezqMXeyqYkRkSKeYwgF6AE" +
                "BuoYkI_uRespqYLLpSKX3nvk7giO5HUO9OsHMWQdhb-Xg1V1lL3_alG7YAfK7wAnKLp2-AYvD0c60l-el4TGoGAAABAkBS4SbAwuB9" +
                "rcGy1XcgsH5wxNRV72x1H2rjtH6iMxWA1IiEgQKbWY_06TQgpqF5Z7bUvb_rREfHfLfo3wBF2tCzAECG9LMnvjqjN_VfZNl6qoITSK" +
                "jFe8d2DYJn4xbmsRBXTksnWBy54j8ovGkWdJeInCEQYdaaT9aUvtTyKpJj1IJXAAA=";

        byte[] ekm = new byte[] {-22, 61, 72, -105, 56, 73, -100, 5, -96, -83, -16, 104, -39, -19, -72, -39, 86, 77, -73,
                -85, -62, 35, 55, 74, -15, -97, -4, -43, -82, -33, 92, -72};

        TokenBindingMessage tbMessage = TokenBindingMessage.fromBase64urlEncoded(encoded, ekm);
        assertThat(2, equalTo(tbMessage.getTokenBindings().size()));
        TokenBinding providedTokenBinding = tbMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(providedTokenBinding.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(providedTokenBinding.getKeyParamsIdentifier()));
        assertNotNull(providedTokenBinding.getOpaqueTokenBindingID());
        TokenBinding referred = tbMessage.getReferredTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(referred.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(referred.getKeyParamsIdentifier()));
        assertNotNull(referred.getOpaqueTokenBindingID());

    }
}
