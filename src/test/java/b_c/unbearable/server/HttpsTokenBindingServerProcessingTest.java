package b_c.unbearable.server;

import b_c.unbearable.messages.SignatureResult;
import b_c.unbearable.messages.TokenBinding;
import b_c.unbearable.messages.TokenBindingKeyParameters;
import b_c.unbearable.messages.TokenBindingMessage;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    public void v0_10_providedAndReferredECDSAP256() throws Exception
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
