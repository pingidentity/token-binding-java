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
    public void v0_10_providedAndReferredECDSAP256() throws IOException
    {
        String encoded = "ARIAAgBBQLlO7EVk3V2g3-zmgRpq2qKfbw6F1rZ97Y15siYmjuy3U5CKNcwXnrHYqM87PcilegJ7Ooxd7KpiRGRIp5jCAXo" +
                "AQKCfxPn5RCH0HoR-x_iQOKC46L4MbtCr4WGuXTV8l3VkhVEGl4kscDlWWUcDQV_Mai2HeSiehM8hByu4Y80c7Z0AAAECAEFAUuEmwML" +
                "gfa3BstV3ILB-cMTUVe9sdR9q47R-ojMVgNSIhIECm1mP9Ok0IKaheWe21L2_60RHx3y36N8ARdrQswBA-qmCWGt8PDBwLHEwrEwsYBe" +
                "tZj_DsyZE6O3KeGWjFjsBoXclGUQx8CYtkOfILT2PQVyr-o3fMNr2Cf_FSPjXQgAA";

        byte[] ekm = new byte[] {69,-38,67,-123,84,79,45,24,-108,55,-29,-128,-83,2,-34,45,1,1,-121,85,34,-44,-79,-105,-82,
                124,-92,87,20,-52,65,36};

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

    @Test
    public void v0_10_providedECDSAP256AndUnknownReferred() throws IOException
    {
        byte unknownType = 96;
        byte[] tokenBindingMessage = {1,18,0,2,0,65,64,-71,78,-20,69,100,-35,93,-96,-33,-20,-26,-127,26,106,-38,-94,-97,111,14,-123,-42,
                -74,125,-19,-115,121,-78,38,38,-114,-20,-73,83,-112,-118,53,-52,23,-98,-79,-40,-88,-49,59,61,-56,-91,122,2,123,58,-116,
                93,-20,-86,98,68,100,72,-89,-104,-62,1,122,0,64,-96,-97,-60,-7,-7,68,33,-12,30,-124,126,-57,-8,-112,56,-96,-72,-24,-66,
                12,110,-48,-85,-31,97,-82,93,53,124,-105,117,100,-123,81,6,-105,-119,44,112,57,86,89,71,3,65,95,-52,106,45,-121,121,40,
                -98,-124,-49,33,7,43,-72,99,-51,28,-19,-99,0,0,1,unknownType,0,65,64,82,-31,38,-64,-62,-32,125,-83,-63,-78,-43,119,32,-80,126,112,
                -60,-44,85,-17,108,117,31,106,-29,-76,126,-94,51,21,-128,-44,-120,-124,-127,2,-101,89,-113,-12,-23,52,32,-90,-95,121,103,
                -74,-44,-67,-65,-21,68,71,-57,124,-73,-24,-33,0,69,-38,-48,-77,0,64,-6,-87,-126,88,107,124,60,48,112,44,113,48,-84,76,44,
                96,23,-83,102,63,-61,-77,38,68,-24,-19,-54,120,101,-93,22,59,1,-95,119,37,25,68,49,-16,38,45,-112,-25,-56,45,61,-113,65,
                92,-85,-6,-115,-33,48,-38,-10,9,-1,-59,72,-8,-41,66,0,0};

        byte[] ekm = new byte[] {69,-38,67,-123,84,79,45,24,-108,55,-29,-128,-83,2,-34,45,1,1,-121,85,34,-44,-79,-105,-82,
                124,-92,87,20,-52,65,36};

        TokenBindingMessage tbMessage = TokenBindingMessage.fromBytes(tokenBindingMessage, ekm);
        assertThat(2, equalTo(tbMessage.getTokenBindings().size()));
        TokenBinding providedTokenBinding = tbMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(providedTokenBinding.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(providedTokenBinding.getKeyParamsIdentifier()));
        assertNotNull(providedTokenBinding.getOpaqueTokenBindingID());
        TokenBinding referred = tbMessage.getReferredTokenBinding();
        assertThat(SignatureResult.Status.UNEVALUATED, equalTo(referred.getSignatureResult().getStatus()));
        String msg = referred.getSignatureResult().getCommentary().iterator().next();
        assertThat(msg, containsString(String.valueOf(unknownType)));
        assertThat(unknownType, equalTo(referred.getKeyParamsIdentifier()));
        assertNotNull(referred.getOpaqueTokenBindingID());
    }

    @Test
    public void v0_10_UnknownProvidedAndReferredECDSAP256() throws IOException
    {
        byte unknownType = 96;
        byte[] tokenBindingMessage = {1,18,0,unknownType,0,65,64,-71,78,-20,69,100,-35,93,-96,-33,-20,-26,-127,26,106,-38,-94,-97,111,14,-123,-42,
                -74,125,-19,-115,121,-78,38,38,-114,-20,-73,83,-112,-118,53,-52,23,-98,-79,-40,-88,-49,59,61,-56,-91,122,2,123,58,-116,
                93,-20,-86,98,68,100,72,-89,-104,-62,1,122,0,64,-96,-97,-60,-7,-7,68,33,-12,30,-124,126,-57,-8,-112,56,-96,-72,-24,-66,
                12,110,-48,-85,-31,97,-82,93,53,124,-105,117,100,-123,81,6,-105,-119,44,112,57,86,89,71,3,65,95,-52,106,45,-121,121,40,
                -98,-124,-49,33,7,43,-72,99,-51,28,-19,-99,0,0,1,2,0,65,64,82,-31,38,-64,-62,-32,125,-83,-63,-78,-43,119,32,-80,126,112,
                -60,-44,85,-17,108,117,31,106,-29,-76,126,-94,51,21,-128,-44,-120,-124,-127,2,-101,89,-113,-12,-23,52,32,-90,-95,121,103,
                -74,-44,-67,-65,-21,68,71,-57,124,-73,-24,-33,0,69,-38,-48,-77,0,64,-6,-87,-126,88,107,124,60,48,112,44,113,48,-84,76,44,
                96,23,-83,102,63,-61,-77,38,68,-24,-19,-54,120,101,-93,22,59,1,-95,119,37,25,68,49,-16,38,45,-112,-25,-56,45,61,-113,65,
                92,-85,-6,-115,-33,48,-38,-10,9,-1,-59,72,-8,-41,66,0,0};

        byte[] ekm = new byte[] {69,-38,67,-123,84,79,45,24,-108,55,-29,-128,-83,2,-34,45,1,1,-121,85,34,-44,-79,-105,-82,
                124,-92,87,20,-52,65,36};

        TokenBindingMessage tbMessage = TokenBindingMessage.fromBytes(tokenBindingMessage, ekm);
        assertThat(2, equalTo(tbMessage.getTokenBindings().size()));
        TokenBinding providedTokenBinding = tbMessage.getProvidedTokenBinding();
        assertThat(providedTokenBinding.getSignatureResult().getStatus(), equalTo(SignatureResult.Status.UNEVALUATED));
        String msg = providedTokenBinding.getSignatureResult().getCommentary().iterator().next();
        assertThat(msg, containsString(String.valueOf(unknownType)));
        assertThat(providedTokenBinding.getKeyParamsIdentifier(), equalTo(unknownType));
        assertNotNull(providedTokenBinding.getOpaqueTokenBindingID());
        TokenBinding referred = tbMessage.getReferredTokenBinding();
        assertThat(referred.getSignatureResult().getStatus(), equalTo( SignatureResult.Status.VALID));
        assertThat(referred.getKeyParamsIdentifier(), equalTo(TokenBindingKeyParameters.ECDSAP256));
        assertNotNull(referred.getOpaqueTokenBindingID());
    }
}
