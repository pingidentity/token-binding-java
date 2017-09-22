package b_c.unbearable.server;

import b_c.unbearable.client.TokenBindingMessageMaker;
import b_c.unbearable.messages.SignatureResult;
import b_c.unbearable.messages.TokenBinding;
import b_c.unbearable.messages.TokenBindingKeyParameters;
import b_c.unbearable.messages.TokenBindingMessage;
import b_c.unbearable.utils.EcKeyUtil;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Base64;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

/**
 *
 */
public class HttpsTokenBindingServerProcessingTest
{
    private static final Logger log = LoggerFactory.getLogger(HttpsTokenBindingServerProcessingTest.class);


    @Test
    public void v0_10_notsure_from_edge() throws Exception
    {
        // from Andrei's private reply to https://www.ietf.org/mail-archive/web/unbearable/current/msg01332.html
        // and log files

        String encoded = "AIkAAgBBQJ5dTpA66QvSRCFhAf-5G4Xg_UbXiMZyBNvxNz3KgEfPcyhFTUMxa0vT4yc-oZKocTnWWkMd9voV7ADQdaMI5zkAQASTZuLhUlwSYwjyYHx0rLrAYfXuxzep3wdecyRyvD1Y1wiV3OzurR2Ad6WW3M-FWxB5dON0c7UIiAV4c06C7KUAAA";

        byte[] ekm = new byte[] {-4, -53, -33, 70, 27, -117, 62, -44, 51, 28, 49, -38, 84, 0, -22, 55, 22, -105, -8, 70, -120, -21, -76, 118, 112, -26, 77, 44, -106, 34, -98, -122};


        // check it with HttpsTokenBindingServerProcessing
        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
        TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encoded, TokenBindingKeyParameters.ECDSAP256, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));

        // check that HttpsTokenBindingServerProcessing will reject it when the negotiated key parameters don't match
        try
        {
            tokenBindingMessage = htbsp.processSecTokenBindingHeader(encoded, TokenBindingKeyParameters.RSA2048_PKCS1_5, ekm);
            fail(tokenBindingMessage + " shouldn't have gotten here due to invalid signature");
        }
        catch (TBException e)
        {
            log.debug("Expected this with invalid signature: " + e);
        }


        // now change the ekm and make sure it parses but has an invalid signature
        ekm[0] = 77;

        // check that HttpsTokenBindingServerProcessing will reject it
        try
        {
            tokenBindingMessage = htbsp.processSecTokenBindingHeader(encoded, TokenBindingKeyParameters.ECDSAP256, ekm);
            fail(tokenBindingMessage + " shouldn't have gotten here due to invalid signature");
        }
        catch (TBException e)
        {
            log.debug("Expected this with invalid signature: " + e);
        }

    }

    @Test
    public void providedAndReferredECDSAP256() throws Exception
    {
        String encoded = "ARIAAgBBQLlO7EVk3V2g3-zmgRpq2qKfbw6F1rZ97Y15siYmjuy3U5CKNcwXnrHYqM87PcilegJ7Ooxd7KpiRGRIp5jCAXo" +
                "AQKCfxPn5RCH0HoR-x_iQOKC46L4MbtCr4WGuXTV8l3VkhVEGl4kscDlWWUcDQV_Mai2HeSiehM8hByu4Y80c7Z0AAAECAEFAUuEmwML" +
                "gfa3BstV3ILB-cMTUVe9sdR9q47R-ojMVgNSIhIECm1mP9Ok0IKaheWe21L2_60RHx3y36N8ARdrQswBA-qmCWGt8PDBwLHEwrEwsYBe" +
                "tZj_DsyZE6O3KeGWjFjsBoXclGUQx8CYtkOfILT2PQVyr-o3fMNr2Cf_FSPjXQgAA";

        byte[] ekm = new byte[] {69,-38,67,-123,84,79,45,24,-108,55,-29,-128,-83,2,-34,45,1,1,-121,85,34,-44,-79,-105,-82,
                124,-92,87,20,-52,65,36};

        // check it with HttpsTokenBindingServerProcessing too
        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
        TokenBindingMessage tbMessage = htbsp.processSecTokenBindingHeader(encoded, TokenBindingKeyParameters.ECDSAP256, ekm);

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
    public void providedECDSAP256AndUnknownReferred() throws Exception
    {
        byte unknownType = 96;

        byte[] ekm = new byte[] {69,-38,67,-123,84,79,45,24,-108,55,-29,-128,-83,2,-34,45,1,1,-121,85,34,-44,-79,-105,-82,
                124,-92,87,20,-52,65,36};

        // this has an unknown type 96 for the Referred
        String encodedTokenBindingMessage = "ARIAAgBBQLlO7EVk3V2g3-zmgRpq2qKfbw6F1rZ97Y15siYmjuy3U5CKNcwXnrHYqM87PcilegJ7Ooxd7KpiRGRIp" +
                "5jCAXoAQKCfxPn5RCH0HoR-x_iQOKC46L4MbtCr4WGuXTV8l3VkhVEGl4kscDlWWUcDQV_Mai2HeSiehM8hByu4Y80c7Z0AAAFgAEFAUuEmwMLgfa3Bst" +
                "V3ILB-cMTUVe9sdR9q47R-ojMVgNSIhIECm1mP9Ok0IKaheWe21L2_60RHx3y36N8ARdrQswBA-qmCWGt8PDBwLHEwrEwsYBetZj_DsyZE6O3KeGWjFjs" +
                "BoXclGUQx8CYtkOfILT2PQVyr-o3fMNr2Cf_FSPjXQgAA";

        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
        TokenBindingMessage tbMessage = htbsp.processSecTokenBindingHeader(encodedTokenBindingMessage, TokenBindingKeyParameters.ECDSAP256, ekm);

        // it won't fail with unknown referred but will have an UNEVALUATED signature status

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
    public void providedUnknownKeyParamType() throws IOException
    {

        // this has an unknown type 88 for the provided
        String encodedTokenBindingMessage = "AIkAWABBQLlO7EVk3V2g3-zmgRpq2qKfbw6F1rZ97Y15siYmjuy3U5CKNcwXnrHYqM87PcilegJ7Ooxd7KpiRGRIp5jCA" +
                "XoAQCLhZIeSUTWv3ETKb9qPDyWzxmQlwFDFkmeGSophCtEEdfOnsKotZNOgQ3Fz3DIwHZb-GqdkjoHiVN_hAE5dG-gAAA";

        byte[] ekm = new byte[] {-25, 60, -5, -91, -81, 127, -84, -127, -124, -17, -42, 106, -11, -15, 20, -98, 95,
                -110, 108, -80, -91, -86, 77, 74, -11, -74, -84, -10, 21, -103, -5, -4};

        // check that HttpsTokenBindingServerProcessing will reject it b/c the signature on provided has to be valid
        try
        {
            HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
            TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encodedTokenBindingMessage, TokenBindingKeyParameters.ECDSAP256, ekm);
            fail(tokenBindingMessage + " shouldn't have gotten here due to invalid signature");
        }
        catch (TBException e)
        {
            log.debug("Expected this with invalid signature: " + e);
        }
    }

    @Test
    public void invalidProvidedWithReferred() throws Exception
    {
        byte[] ekm = new byte[] {69,-38,67,-123,84,79,45,24,-108,55,-29,-128,-83,2,-34,45,1,1,-121,85,34,-44,-79,-105,-82,
                124,-92,87,20,-52,65,36};

        // this has an bad signature for the provided
        String encodedTokenBindingMessage = "ARIAAgBBQPusDOl2NCshBN3KqvA5Te7UB97ZDaWPn5q9rxdQAeq1jYjxKCrCm3DngLv-052rD1FVSJB" +
                "4Y0IX8zQpkW0j30UAQE1w67CX_a9J1r3CgLXjaqXG5ygQQ4OZ6TjxKP482f5zia73yBHZ1QkT2SaiG2-UA_8CJ_WjxVyb9yOOyaLf4A4AAA" +
                "ECAEFAvzWwAVQVi14QqfneeES37QwejO17eSQnj31jskiN5WW2SK88Bw8VoCwm5YS-m2x54VKMoQoaqjrtk14AMI5FuQBAk-XVi-LkJ7JoR" +
                "Fg2bACp0eWJq0LhjRC9Ok9rzTORrmzEZ7nGsVwmM1Joue8K7vMlBJV2OMS0_4CeM1Sp8xxxrwAA";

        // check that HttpsTokenBindingServerProcessing will reject it the signature on provided is invalid
        try
        {
            HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
            TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encodedTokenBindingMessage, TokenBindingKeyParameters.ECDSAP256, ekm);
            fail(tokenBindingMessage + " shouldn't have gotten here due to invalid signature");
        }
        catch (TBException e)
        {
            log.debug("Expected this with invalid signature: " + e);
        }
    }

    @Test
    public void providedECDSAP256AndInvalidReferred() throws Exception
    {

        byte[] ekm = new byte[] {69,-38,67,-123,84,79,45,24,-108,55,-29,-128,-83,2,-34,45,1,1,-121,85,34,-44,-79,-105,-82,
                124,-92,87,20,-52,65,36};

        // this has an bad signature for the Referred
        String encodedTokenBindingMessage = "ARIAAgBBQEHHROWb1IILIsSlJf14UpL3s7BcgCm-nQ8iJgz1KsVY9cQBuynpqeLVr1G-jtc3wlFX2f" +
                "7ACOiTg4TCbsHV-Q4AQENLTGKLQOaEi3Q9Fdug0bAvQMN4KyykwuoVg41n_CFGYRhtlWTYeALTBIdjSxmvR1pbgra4OG_KsyyIN86XDXYA" +
                "AAECAEFAVYp9rmu2-xKkn9ersM14hEDL43wJePMRgsgdJrwGCpJFgV9WP2KOqjHApYIoJW-GEipxkZvQLCazDhXg64t7zgBASCDNhN2YpO" +
                "3MRCEIP1zTrhMvB-A3i9pmSLBZGG6pgF3hF0-hnw--IXdxW47Hl50Cs3I15WWkesNpVa9UwsUqTQAA";

        // check that HttpsTokenBindingServerProcessing will reject it the signature on referred is invalid
        try
        {
            HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
            TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encodedTokenBindingMessage, TokenBindingKeyParameters.ECDSAP256, ekm);
            fail(tokenBindingMessage + " shouldn't have gotten here due to invalid signature");
        }
        catch (TBException e)
        {
            log.debug("Expected this with invalid signature: " + e);
        }
    }

    @Test
    public void empty_tb_msg() throws Exception
    {
        // Saw some errors at
        // https://www.ietf.org/mail-archive/web/unbearable/current/msg01332.html
        // that were the result of AAA being sent as the Sec-Token-Binding header
        String encoded = "AAA";
        byte[] ekm = new byte[] {-116, 19, 118, -122, 78, 115, 98, 116, -124, -110, -62, -108, -59, 63, -39, -119, -123, 124, -39, -3, -7, 94, 18, 10, 67, -79, -94, 67, -108, 61, 103, -112};

        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
        try
        {
            TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encoded, TokenBindingKeyParameters.ECDSAP256, ekm);
            fail(tokenBindingMessage + " HttpsTokenBindingServerProcessing processSecTokenBindingHeader should fail on " + encoded);
        }
        catch (TBException e)
        {
            log.debug("Expected this trying to process Sec-Token-Binding of " + encoded + ": " + e);
        }
    }
}
