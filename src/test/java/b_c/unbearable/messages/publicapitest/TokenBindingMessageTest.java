package b_c.unbearable.messages.publicapitest;

import b_c.unbearable.messages.SignatureResult;
import b_c.unbearable.messages.TokenBinding;
import b_c.unbearable.messages.TokenBindingKeyParameters;
import b_c.unbearable.messages.TokenBindingMessage;
import org.junit.Test;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.junit.Assert.assertArrayEquals;

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


    @Test
    public void v0_13_singleProvidedECDSAP256() throws IOException
    {
        // also used in Token Binding for Refresh Tokens Example in https://tools.ietf.org/html/draft-ietf-oauth-token-binding-02
        String encodedTBM = "AIkAAgBBQGto7hHRR0Y5nkOWqc9KNfwW95dEFmSI_tCZ_Cbl7LWlt6Xjp3DbjiDJavGFiKP2HV_2JSE42VzmKOVVV8" +
                "m7eqAAQOKiDK1Oi0z6v4X5BP7uc0pFestVZ42TTOdJmoHpji06Qq3jsCiCRSJx9ck2fWJYx8tLVXRZPATB3x6c24aY0ZEAAA";

        byte[] ekm = new byte[] {-89, -90, 110, 75, 7, -27, -22, -110, 30, -15, -21, 57, 43, 39, -107, -17, -92, -8,
                -77, 6, 102, 66, -99, 63, 107, 7, 118, -18, 49, -33, -83, -70};
//        System.out.println("TB: " + encodedTBM);
        String encodedEkm = Base64.getUrlEncoder().encodeToString(ekm);
        encodedEkm = encodedEkm.replaceAll("=", "");
//        System.out.println("EKM: " + encodedEkm);
        ekm = Base64.getUrlDecoder().decode(encodedEkm);

        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBase64urlEncoded(encodedTBM, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        byte[] opaqueTokenBindingID = provided.getOpaqueTokenBindingID();
        String encodedTBID = Base64.getUrlEncoder().encodeToString(opaqueTokenBindingID);
//        System.out.println("TBID: " + encodedTBID.replaceAll("=", ""));
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());

        encodedTBM = "AIkAAgBBQGto7hHRR0Y5nkOWqc9KNfwW95dEFmSI_tCZ_Cbl7LWlt6Xjp3DbjiDJavGFiKP2HV_2JSE42VzmKOVVV8m7eqAA" +
                "QCpGbaG_YRf27qOraL0UT4fsKKjL6PukuOT00qzamoAXxOq7m_id7O3mLpnb_sM7kwSxLi7iNHzzDgCAkPt3lHwAAA";
        ekm = new byte[] {-67, -81, -68, -31, 73, 48, -31, -102, -97, 119, -69, -106, 58, -47, 107, 0, -105, 90, -9,
                -91, -80, -127, -73, 90, 60, 53, -10, -110, 122, 14, -120, 1};
//        System.out.println("TB: " + encodedTBM);
        encodedEkm = Base64.getUrlEncoder().encodeToString(ekm);
        encodedEkm = encodedEkm.replaceAll("=", "");
//        System.out.println("EKM: " + encodedEkm);
        ekm = Base64.getUrlDecoder().decode(encodedEkm);
        tokenBindingMessage = TokenBindingMessage.fromBase64urlEncoded(encodedTBM, ekm);
        assertThat(SignatureResult.Status.VALID, equalTo(tokenBindingMessage.getProvidedTokenBinding().getSignatureResult().getStatus()));
        assertArrayEquals(opaqueTokenBindingID, tokenBindingMessage.getProvidedTokenBinding().getOpaqueTokenBindingID());
    }

    @Test
    public void v0_13_singleProvidedECDSAP256_again() throws Exception
    {
        // also used in Token Binding for Refresh Tokens Example in https://tools.ietf.org/html/draft-ietf-oauth-token-binding-02
        String encodedTBM = "AIkAAgBBQLgtRpWFPN66kxhxGrtaKrzcMtHw7HV8yMk_-MdRXJXbDMYxZCWnCASRRrmHHHL5wmpP3bhYt0ChRDbsMapfh_QAQN1He3Ftj4Wa_S_fzZVns4saLfj6aBoMSQW6rLs19IIvHze7LrGjKyCfPTKXjajebxp-TLPFZCc0JTqTY5_0MBAAAA";

        byte[] ekm = new byte[] {-20, -69, 13, 63, 112, 83, -43, -95, -57, 117, 119, 100, -22, 103, -124, 90, 59, 82, -110, 35, -43, 45, -66, -40, 75, -88, -121, -89, -30, 87, -102, -31};
//        System.out.println("TB: " + encodedTBM);
        String encodedEkm = Base64.getUrlEncoder().encodeToString(ekm);
        encodedEkm = encodedEkm.replaceAll("=", "");
//        System.out.println("EKM: " + encodedEkm);
        ekm = Base64.getUrlDecoder().decode(encodedEkm);

        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBase64urlEncoded(encodedTBM, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        byte[] opaqueTokenBindingID = provided.getOpaqueTokenBindingID();
        String encodedTBID = Base64.getUrlEncoder().encodeToString(opaqueTokenBindingID);
//        System.out.println("TBID: " + encodedTBID.replaceAll("=", ""));
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] tbhBytes = digest.digest(opaqueTokenBindingID);
        String tbh = Base64.getUrlEncoder().encodeToString(tbhBytes);
        tbh = tbh.replaceAll("=", "");
//        System.out.println("TBH: " + tbh);
    }


    @Test
    public void v0_13_singleProvidedECDSAP256_again2() throws Exception
    {
        // also used in Token Binding for Native authz code binding in https://tools.ietf.org/html/draft-ietf-oauth-token-binding-02
        String encodedTBM = "AIkAAgBBQEOO9GRFP-LM0hoWw6-2i318BsuuUum5AL8bt1szlr1EFfp5DMXMNW3O8WjcIXr2DKJnI4xnuGsE6GywQd9RbD0AQJDb3xyo9PBxj8M6YjLt-6OaxgDkyoBoTkyrnNbLc8tJQ0JtXomKzBbj5qPtHDduXc6xz_lzvNpxSPxi428m7wkAAA";

        byte[] ekm = new byte[] {-92, -43, 74, -76, -5, -112, 22, -4, -91, 53, -119, -12, -45, 68, 40, -63, 106, -48, 42, -121, -116, -111, -27, -3, 31, 125, -95, 86, -27, 59, -44, 27};
//        System.out.println("TB: " + encodedTBM);
        String encodedEkm = Base64.getUrlEncoder().encodeToString(ekm);
        encodedEkm = encodedEkm.replaceAll("=", "");
//        System.out.println("EKM: " + encodedEkm);
        ekm = Base64.getUrlDecoder().decode(encodedEkm);

        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBase64urlEncoded(encodedTBM, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        byte[] opaqueTokenBindingID = provided.getOpaqueTokenBindingID();
        String encodedTBID = Base64.getUrlEncoder().encodeToString(opaqueTokenBindingID);
//        System.out.println("TBID: " + encodedTBID.replaceAll("=", ""));
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] tbhBytes = digest.digest(opaqueTokenBindingID);
        String tbh = Base64.getUrlEncoder().encodeToString(tbhBytes);
        tbh = tbh.replaceAll("=", "");
//        System.out.println("TBH: " + tbh);
    }


    @Test
    public void v0_13_providedAndReferredECDSAP256() throws Exception
    {
        // used in Protected Resource Token Binding Validation Example in https://tools.ietf.org/html/draft-ietf-oauth-token-binding-02
        String encoded = "ARIAAgBBQIEE8mSMtDy2dj9EEBdXaQT9W3Rq1NS-jW8ebPoF6FyL0jIfATVE55zlircgOTZmEg1xeIrC3DsGegwjs4bhw14AQGKDlAXFFMyQkZegCwlbTlqX3F9HTt-lJxFU_pi16ezka7qVRCpSF0BQLfSqlsxMbYfSSCJX1BDtrIL7PXj__fUAAAECAEFA1BNUnP3te5WrwlEwiejEz0OpesmC5PElWc7kZ5nlLSqQTj1ciIp5vQ30LLUCyM_a2BYTUPKtd5EdS-PalT4t6ABADgeizRa5NkTMuX4zOdC-R4cLNWVVO8lLu2Psko-UJLR_XAH4Q0H7-m0_nQR1zBN78nYMKPvHsz8L3zWKRVyXEgAA";

        byte[] ekm = new byte[] {-116, -114, 84, 3, 40, -20, -27, 112, -113, 33, 37, 6, 64, -116, 32, 113, 42, -50, -119, 82, 22, -85, -121, -31, 45, 82, 5, 77, 14, 39, 47, 23};

        String encodedEkm = Base64.getUrlEncoder().encodeToString(ekm);
        encodedEkm = encodedEkm.replaceAll("=", "");
//        System.out.println("EKM: " + encodedEkm);
        ekm = Base64.getUrlDecoder().decode(encodedEkm);
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
        byte[] opaqueReferredTokenBindingID = referred.getOpaqueTokenBindingID();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] tbhBytes = digest.digest(opaqueReferredTokenBindingID);
        String tbh = Base64.getUrlEncoder().encodeToString(tbhBytes);
        tbh = tbh.replaceAll("=", "");
//        System.out.println("TBH: " + tbh);
    }

    @Test
    public void v0_13_providedAndReferredECDSAP256_again() throws Exception
    {
        // used in Access Tokens Issued from the Authorization Endpoint Example in https://tools.ietf.org/html/draft-ietf-oauth-token-binding-02
        String encoded = "ARIAAgBBQJFXJir2w4gbJ7grBx9uTYWIrs9V50-PW4ZijegQ0LUM-_bGnGT6DizxUK-m5n3dQUIkeH7ybn6wb1C5dGyV_IAAQDDFToFrHt41Zppq7u_SEMF_E-KimAB-HewWl2MvZzAQ9QKoWiJCLFiCkjgtr1RrA2-jaJvoB8o51DTGXQydWYkAAAECAEFAuC1GlYU83rqTGHEau1oqvNwy0fDsdXzIyT_4x1FcldsMxjFkJacIBJFGuYcccvnCak_duFi3QKFENuwxql-H9ABAMcU7IjJOUA4IyE6YoEcfz9BMPQqwM5M6hw4RZNQd58fsTCCslQE_NmNCl9JXy4NkdkEZBxqvZGPr0y8QZ_bmAwAA";

        byte[] ekm = new byte[] {-30, 52, -36, -27, -19, 80, -90, -121, 42, 61, 54, 121, -105, -88, -20, 111, -86, 81, 63, 95, 8, 20, -89, 112, -64, -5, -38, -79, -120, -25, -41, -31};
        String encodedEkm = Base64.getUrlEncoder().encodeToString(ekm);
        encodedEkm = encodedEkm.replaceAll("=", "");
//        System.out.println("EKM: " + encodedEkm);
        ekm = Base64.getUrlDecoder().decode(encodedEkm);
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
        byte[] opaqueReferredTokenBindingID = referred.getOpaqueTokenBindingID();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] tbhBytes = digest.digest(opaqueReferredTokenBindingID);
        String tbh = Base64.getUrlEncoder().encodeToString(tbhBytes);
        tbh = tbh.replaceAll("=", "");
//        System.out.println("TBH: " + tbh);

    }

    @Test
    public void v0_13_providedAndReferredECDSAP256_again2() throws Exception
    {
        // used in Access Tokens Issued from web server client code binding in https://tools.ietf.org/html/draft-ietf-oauth-token-binding-02
        String encoded = "ARIAAgBBQB-XOPf5ePlf7ikATiAFEGOS503lPmRfkyymzdWwHCxl0njjxC3D0E_OVfBNqrIQxzIfkF7tWby2ZfyaE6XpwTsAQBYqhFX78vMOgDX_Fd_b2dlHyHlMmkIz8iMVBY_reM98OUaJFz5IB7PG9nZ11j58LoG5QhmQoI9NXYktKZRXxrYAAAECAEFAdUFTnfQADkn1uDbQnvJEk6oQs38L92gv-KO-qlYadLoDIKe2h53hSiKwIP98iRj_unedkNkAMyg9e2mY4Gp7WwBAeDUOwaSXNz1e6gKohwN4SAZ5eNyx45Mh8VI4woL1BipLoqrJRoK6dxFkWgHRMuBROcLGUj5PiOoxybQH_Tom3gAA";

        byte[] ekm = new byte[] {-18, 3, -99, 71, 51, 33, 61, -29, -66, -43, -116, 25, 26, 105, -43, 31, 36, 94, 55, -101, -35, -40, 44, 92, -79, 16, 77, -21, -43, 30, -31, -62};
        String encodedEkm = Base64.getUrlEncoder().encodeToString(ekm);
        encodedEkm = encodedEkm.replaceAll("=", "");
//        System.out.println("EKM: " + encodedEkm);
        ekm = Base64.getUrlDecoder().decode(encodedEkm);
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
        byte[] opaqueReferredTokenBindingID = referred.getOpaqueTokenBindingID();

//        System.out.println();


        // just provided
        encoded = "AIkAAgBBQHVBU530AA5J9bg20J7yRJOqELN_C_doL_ijvqpWGnS6AyCntoed4UoisCD_fIkY_7p3nZDZADMoPXtpmOBqe1sAQEwgC9Zpg7QFCDBib6GlZki3MhH32KNfLefLJc1vR1xE8l7OMfPLZHP2Woxh6rEtmgBcAABubEbTz7muNlLn8uoAAA";

        ekm = new byte[] {19, 53, -70, -46, -4, -120, 53, -69, 27, -2, -42, -93, -73, -56, -93, -34, -43, 122, 115, 12, -74, 40, 127, -94, -16, 23, 68, 49, -123, -36, 54, 125};
        encodedEkm = Base64.getUrlEncoder().encodeToString(ekm);
        encodedEkm = encodedEkm.replaceAll("=", "");
//        System.out.println("EKM: " + encodedEkm);
        ekm = Base64.getUrlDecoder().decode(encodedEkm);

        tbMessage = TokenBindingMessage.fromBase64urlEncoded(encoded, ekm);
        assertThat(1, equalTo(tbMessage.getTokenBindings().size()));
        providedTokenBinding = tbMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(providedTokenBinding.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(providedTokenBinding.getKeyParamsIdentifier()));

        assertArrayEquals(opaqueReferredTokenBindingID, tbMessage.getProvidedTokenBinding().getOpaqueTokenBindingID());

        String tbid = Base64.getUrlEncoder().encodeToString(opaqueReferredTokenBindingID);
        tbid = tbid.replaceAll("=", "");
//        System.out.println("tbid: " + tbid);
    }
}
