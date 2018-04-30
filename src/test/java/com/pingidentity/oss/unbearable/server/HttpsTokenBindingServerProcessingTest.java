package com.pingidentity.oss.unbearable.server;

import com.pingidentity.oss.unbearable.TokenBindingException;
import com.pingidentity.oss.unbearable.messages.SignatureResult;
import com.pingidentity.oss.unbearable.messages.TokenBinding;
import com.pingidentity.oss.unbearable.messages.TokenBindingKeyParameters;
import com.pingidentity.oss.unbearable.messages.TokenBindingMessage;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

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
        expectEx(encoded, TokenBindingKeyParameters.RSA2048_PKCS1_5, ekm);


        // now change the ekm and make sure it has an invalid signature and check that HttpsTokenBindingServerProcessing will reject it
        ekm[0] = 77;
        expectEx(encoded, TokenBindingKeyParameters.ECDSAP256, ekm);

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
    public void providedECDSAP256AndUnknownUnknown() throws Exception
    {
        byte unknownKeyParamsType = 99;
        byte unknownTokenBindingType = 77;

        byte[] ekm = new byte[] {22, 77, 94, -71, -1, -4, 91, -16, 12, 61, -19, 67, 32, 2, -17, 75, 27, -49,
                17, -97, -55, 88, 83, -2, -115, -9, 49, -49, -34, -91, 53, -71};


        // this has an unknown key params type 99 with an unknown token binding type 77
        String encodedTokenBindingMessage = "ARIAAgBBQNpG_mKgtHcfObvmqg8c_iBCkMmaKVbOW_i_fntql1a4oXwoF6aIJP" +
                "2EZrSJIVYf5EjSrgtfBrNnuaj-Rt-qeioAQBisSOpLsptrbTQNV6qYLMoIjVa-wCjqy4Bi-Fg9nSKBBBvExRD1Px5z" +
                "000B7uCun8D-D-z3aQrMv8-NBXzaaawAAE1jAEFADGUjQx-HH-8twvLjZw___QmDXPkEi8aFEkgIxFJNaZ-Rt4eIdF" +
                "2ivZp7-sDUbVcI8pkFiD1nghDxlM7BEKVg9gBAbzY839OpT1HOyUpzWN7gRT0oioiA-sdVp0yDEBdoHSVSK19zTbDx" +
                "MXRttYJSlT-GZShmcK6MjlVLtXgxBLpLWAAA";

        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
        TokenBindingMessage tbMessage = htbsp.processSecTokenBindingHeader(encodedTokenBindingMessage, TokenBindingKeyParameters.ECDSAP256, ekm);

        // it won't fail with unknown but will have an UNEVALUATED signature status

        assertThat(2, equalTo(tbMessage.getTokenBindings().size()));
        TokenBinding providedTokenBinding = tbMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(providedTokenBinding.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(providedTokenBinding.getKeyParamsIdentifier()));
        assertNotNull(providedTokenBinding.getOpaqueTokenBindingID());
        TokenBinding other = tbMessage.getTokenBindingByType(unknownTokenBindingType);
        assertThat(SignatureResult.Status.UNEVALUATED, equalTo(other.getSignatureResult().getStatus()));
        String msg = other.getSignatureResult().getCommentary().iterator().next();
        assertThat(msg, containsString(String.valueOf(unknownKeyParamsType)));
        assertThat(unknownKeyParamsType, equalTo(other.getKeyParamsIdentifier()));
        assertNotNull(other.getOpaqueTokenBindingID());
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
        expectEx(encodedTokenBindingMessage, TokenBindingKeyParameters.ECDSAP256, ekm);
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
        expectEx(encodedTokenBindingMessage, TokenBindingKeyParameters.ECDSAP256, ekm);
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
        expectEx(encodedTokenBindingMessage, TokenBindingKeyParameters.ECDSAP256, ekm);
    }

    @Test
    public void empty_tb_msg() throws Exception
    {
        // Saw some errors at
        // https://www.ietf.org/mail-archive/web/unbearable/current/msg01332.html
        // that were the result of AAA being sent as the Sec-Token-Binding header
        String encoded = "AAA";
        byte[] ekm = new byte[] {-116, 19, 118, -122, 78, 115, 98, 116, -124, -110, -62, -108, -59, 63, -39, -119, -123, 124, -39, -3, -7, 94, 18, 10, 67, -79, -94, 67, -108, 61, 103, -112};

        expectEx(encoded, TokenBindingKeyParameters.ECDSAP256, ekm);
    }

    @Test
    public void providedECDSAP256fromChromeToJava9Server() throws Exception
    {
        String stb = "AIkAAgBBQBaKc7ww4HVlFLKxCZW8RmttltZ_CvuvHpz5YAR6BCQnbTf3WksAFdBMl6X30JNzJTs4ecIN2aEZUHWGP2Nh0l0AQLlNmE9jrgNVINJMMzLod7G-IcQ74K7448UDqoIm07epCHSrqqGKMN4v06jQzlyNECZaNSFq-SwTlWT309FbSeEAAA";
        byte[] ekm = new byte[] {85, 114, 2, -124, 93, -33, -41, 48, -32, 87, 37, -36, 12, 88, 63, -96, 76, -57, -10, 61, -98, 27, -35, 73, -104, -110, -78, 20, 63, 100, 41, 48};

        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();

        TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(stb, TokenBindingKeyParameters.ECDSAP256, ekm);

        TokenBinding providedTokenBinding = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(providedTokenBinding.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(providedTokenBinding.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());
        assertThat(tokenBindingMessage.getTokenBindings().size(), equalTo(1));
    }

    @Test
    public void validSigWithAnUnknownTokenBindingType() throws Exception
    {
        String encoded = "ARJNAgBBQEMAB6K900ChihKM8SeLe2RhnOM7npn7V3jiqsIQHQpVUAoiDpfpsGrG2Vp3Fj44AJdrQe8RhhxSH_1CHnyp5CcAQInqsLUOvQCm69C_famorZEJ0xbPOee-OZwmcg_8MI6eDJCCAHQ5EDNEk7zkUIFaVZfOsSqGpcwP5iK45yxggN4AAAACAEFAl3koFceIwJ7zX2-0uoj-lM8V1cTH1IKxAYF-6TMbiV3DzVHzlqmXim9gODmDddVBKyYM8LLuSuzbhKt7fMtAyQBALkwA7V_t9dYZoKxlMK0ECzU4AaNOfLNx64TUNZdq-jKNuyN9xmCrCkGj82paBJTGoTC_8lxefKOqRbRTKcQlaQAA";

        byte[] ekm = new byte[] {22, 77, 94, -71, -1, -4, 91, -16, 12, 61, -19, 67, 32, 2, -17, 75, 27, -49, 17, -97, -55, 88, 83, -2, -115, -9, 49, -49, -34, -91, 53, -71};

        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();

        TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encoded, TokenBindingKeyParameters.ECDSAP256, ekm);

        TokenBinding providedTokenBinding = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(providedTokenBinding.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(providedTokenBinding.getKeyParamsIdentifier()));

        assertThat(tokenBindingMessage.getTokenBindings().size(), equalTo(2));

        TokenBinding otherTokenBinding = tokenBindingMessage.getTokenBindingByType(77);
        assertThat(SignatureResult.Status.VALID, equalTo(otherTokenBinding.getSignatureResult().getStatus()));
    }

    @Test
    public void invalidSigWithAnUnknownTokenBindingType() throws Exception
    {
        String encoded = "ARIAAgBBQFeYzlQpH4OMXlTFiz9arUx2ITjnBzIn7Apm8uRVGM_ezoso02sEALt0aIsFdxLqiWU5r61dQ1s1pS5i_mfgPDYAQJNwP9koqMewV3ZwqIbcRrXp-ybOUQf2zj5wPaV_N1zn5VM9lJqCDURvCSGYstdCArWGVnTUjKLNXkZNV9uf5-0AAE0CAEFAYzYsl2uDPwS4nRlpkW9_gxGgxqXwbQED0MSj410-jH9I3UimFE24Q6jJLmU0JLMAJA-5AeGg-ihT-KNNghg7_ABArFnplqF7hj08kFrCaEc4PFYRmA27EpnXt-7Gktto8ab3A0YY_4PBoASYvxGgsF32JH13g2A482KIfvbz9GziAQAA";
        byte[] ekm = new byte[] {22, 77, 94, -71, -1, -4, 91, -16, 12, 61, -19, 67, 32, 2, -17, 75, 27, -49, 17, -97, -55, 88, 83, -2, -115, -9, 49, -49, -34, -91, 53, -71};
        expectEx(encoded, TokenBindingKeyParameters.ECDSAP256, ekm);
    }

    @Test
    public void nullEncodedMessage() throws Exception
    {
        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
        TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(null, null, null);
        assertNull(tokenBindingMessage);
    }

    @Test
    public void tooManyProvided()
    {
        byte[] ekm = new byte[] {34, 17, 4, -1, -51, 66, 91, -16, 12, 33, -19, 67, 32, -92, -17, -117, 42, -86,
                77, -49, -121, 88, 73, 82, -17, 69, 9, -4, -43, -94, -5, 21};
        String stb = "AZsAAgBBQA9g8vzBch9Hn8Ul9AWGUudcly7c7GMCr1_RUv1hhCWjZ_Otd6_dS8oItEH60KMTOvqFqaDPMzv8cVGrtS6l6YUAQJbYMzs7SmiTZ6I8PUrKBQHVccVaakLVv71Ru325x7W4OzYUSmQABbzeyQmKD6xSqtHwcycbrYOYcNWZPH3kaHwAAAECAEFAknKpCb3__SHF94q8l-Jc2KeyGs9r8abD1GaZYHROjNMi5_eAqIb2qUi6b0Q3UNnk1lC3b7sVdhuDzalKNgpmzgBAn_J7-7o-Tqwx4iJh-0vZWApmFYP3L4rOmfoMthvemLP1qeXuESI2ft_GC2zThi9HWuhnrDFmuFXt9dN7wWzAYAAAAAIAQUAtbZ8YIR7Oj4JH50JGbu9ik2r8C-S4TI-xqkLIQZ0CCzTyRyEz7jmFLT-KLVWaJj6z3l8qQLI8Q36G8gadQztQAEB3X26kG3IHomSBX1nO_UAylzYh7EUgbFnG7UYpUkbb6E5mAOcfR_7nZwLtWfOBZn4L0gBdrhj44emDRtLW3vu4AAA";
        expectEx(stb, TokenBindingKeyParameters.ECDSAP256, ekm);
        stb = "A6kCAgBBQNSAC-_xVg4Xnq_yWgE2DKcdd54WQoKRDOAORxKl-m0U5UQjJ9R1rPyJMKTagv-WrEfUGvufnguwrFHWEfN6iN4AQJ05Sq9w-iHwrQ6NJgFudss6_UwcMo8I8pxBmJlk0DxqMMuP1-HeuPimTzmcSpSOVgPfz7HhRWt89dMbCq-ArNoAAAAAAQYBAIzfHQjDbzkX1U3CeVFiXiXo-PxXu5gEw57q0r5lKgjxQ5q1Tq40F9kKkqZa-thyH87RCLaAyqcvfwmam6EQ9oRr5SDrkSw1-hUJ9y4U5ddlJbsyYwGLvYEwBGOoAQaYCR1_D1C7T4ONz-5wvundklNWjQZHADGlvugqzU84D7TYarPu5J_JgLXejq72wE4Xi7kqXSTMld2mDJTlmDkj4jT94vkHUJU7JHXnJ4OkcGpQpJWUKbAuDhOx1fJGHFSSzccOHL7VoX7ZtPuhbfLPssl3bwz6MfWnkbjICXxVul37izhAIPpX7UxfI5E4dXt0Ej1CN_KhGkBKcJgEPDXdoJcDAQABAQA1m_S6IZMGIJ1aKmpaW3cCqtbhKbOAzF82x0Ze1uirYpMlX9ImEDdTDzv-UAsvduh89aTSOc5i8zWHEERdl18YualtoYQd5QmSXUBpdsSvH9JM7RnQzqCl4GzOlFxTZzdoa_-8pPax-yzJmOLHNv0p-WTP_hVSvni8wN01f3MfI_S75gfezMj3_a9q44fbgOsE7-g9De5CTCsObgCRU85RUBs4Jl5KhIt5IErwVMC0blbjoi841wwxt8JOT4cBApxV5v_Y4DC-djG2HsYc9B560Jn-mNs65j5nU2JAE97cr8AduO-Vcp3NnaBAA2IBgWvDIk8sfMLpCRYm1tHrPkPsAAABAgBBQAdkrBBZ-Wi9a5mT3o8lMPlBgmJ59CuHBjg0l9fGMcZDOLC9T8zoFTDdGUT5CYmNhRrI0iF_phPPror1gV0-W6MAQAoUUK3LTndejYG3OyW9v1r2fyjU3Mv1IpBrAzX2eH13unQZDNytgY_iGo7g0v0FpD5oN0beOU1B-Q-YDIuh3hEAAAACAEFAQC4CPnD0_GVc9bDsB8-L-b38dAkfV4JWyyQGE_Schshm3A5fOMe8qtUMyIT3vTjQVOhDb4f1ohmC7L0QdCUdDwBAu9d1Vb5l2L-_lHbDMn-9tVGp5w_EE-GszcIHc7URhIBrzGA9O3B0NZl8suCmV4fZNSAlWpj-QllL4vTb-rlOrQAA";
        expectEx(stb, TokenBindingKeyParameters.RSA2048_PKCS1_5, ekm);
    }

    @Test
    public void tooManyReferred()
    {
        byte[] ekm = new byte[] {22, 77, 94, -71, -1, -4, 91, -16, 12, 61, -19, 67, 32, 2, -17, 75, 27, -49,
                17, -97, -55, 88, 83, -2, -115, -9, 49, -49, -34, -91, 53, -71};
        String stb = "AZsBAgBBQPljZQjBWF1jCg5DPvzE-AWSKrF2JywEVh-pINBTe4AZOt1ASXxJG2o1-RUzS-rh_MeL3EkzvXjQSNe0G2oUfYQAQOs1QAQ0ssDK_VU0S5StBvL46b9gooWynqXWlmpD3PD4y1Zjpz0mNSF3EopsR634jAhNKP1vr7DS9UNK-x2Ttm4AAAACAEFAoghW-IIMUL8r-KEilY_nCsmcgVYK5t33OKbg4gr_rSSYDBuk78WzJuTlTV2EnIdXHwgWHO4RQA6O7caW_RzOzwBAgcx06Db7ZmavsabE8ctEdz-9U8ioi_ODMLQYIPdGtW3OIxx1KGYZg01NLuNfNLTyGxdHqVZFOT47ocCXgINAvwAAAQIAQUD0OpYr264d5BExScjPUtMJM3rCuzDsGowE3Ch42dDnjbQiroJnk8CEFTvf_dNB5HBqCCv49oGwNhaISTvf5a6PAEACQGdaFXasyomPLFpFpjwqv7Xr6647QvL9oxKhuD1GmZpLftfkI-c37fjVLe5_XbaZxbbtlJvvn5jsiSFMCaVeAAA";
        expectEx(stb, TokenBindingKeyParameters.ECDSAP256, ekm);
    }

    @Test
    public void onlyReferred()
    {
        byte[] ekm = new byte[] {22, 77, 94, -71, -1, -4, 91, -16, 12, 61, -19, 67, 32, 2, -17, 75, 27, -49,
                17, -97, -55, 88, 83, -2, -115, -9, 49, -49, -34, -91, 53, -71};
        String encoded = "AIkBAgBBQNoXWJUoq4ryEWs4hQ5mUl4QRwL7vGKqIAvf3rnuB6MdUpKMmp_pz83SNik6nehmEJQHN0ru_7-TgdnhOH1JbggAQBFzmG2v75zW76ffz5z_94V5WtL9a-ty32wH8CCKMZ8aF36-Fm4hnjVygAOYVu2wdmopVF8_YhLcAe9zSOyJhkoAAA";
        expectEx(encoded, TokenBindingKeyParameters.ECDSAP256, ekm);
    }

    @Test
    public void onlyUnknownTokenBindingType()
    {
        byte[] ekm = new byte[] {22, 77, 94, -71, -1, -4, 91, -16, 12, 61, -19, 67, 32, 2, -17, 75, 27, -49,
                17, -97, -55, 88, 83, -2, -115, -9, 49, -49, -34, -91, 53, -71};
        String encoded = "AIlNAgBBQDPGq6i5n--wK05-UBCX5FImTaFMx90Ur1lSUSVLb4izEsmRl-Tcfsq2AZfN_8zrr56QJu8UipZTANkSurczW58AQAquMkSo7ZGG4p5BVVLVnZ6-FrdhX7tMY09XirvoOoCRfajlcIU0LTdAcuAfNJtapi4KoXxI-IWR5qd7bNyWYakAAA";
        expectEx(encoded, TokenBindingKeyParameters.ECDSAP256, ekm);
    }

    private void expectEx(String encoded, Byte negotiatedTbKeyParams, byte[] ekm)
    {
        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
        try
        {
            TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encoded, negotiatedTbKeyParams, ekm);
            fail(tokenBindingMessage + " HttpsTokenBindingServerProcessing processSecTokenBindingHeader should fail on " + encoded);
        }
        catch (TokenBindingException e)
        {
            log.debug("Expected this trying to process Sec-Token-Binding of " + encoded + ": " + e);
        }
    }
    
}
