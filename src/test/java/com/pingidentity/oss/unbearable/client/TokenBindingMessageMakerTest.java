package com.pingidentity.oss.unbearable.client;

import com.pingidentity.oss.unbearable.JceProviderTestSupport;
import com.pingidentity.oss.unbearable.messages.EcdsaP256;
import com.pingidentity.oss.unbearable.messages.SignatureResult;
import com.pingidentity.oss.unbearable.messages.TokenBinding;
import com.pingidentity.oss.unbearable.messages.TokenBindingKeyParameters;
import com.pingidentity.oss.unbearable.messages.TokenBindingMessage;
import com.pingidentity.oss.unbearable.messages.TokenBindingType;
import com.pingidentity.oss.unbearable.server.HttpsTokenBindingServerProcessing;
import com.pingidentity.oss.unbearable.utils.EcKeyUtil;
import com.pingidentity.oss.unbearable.utils.RsaKeyUtil;
import com.pingidentity.oss.unbearable.utils.Util;
import org.hamcrest.CoreMatchers;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 *
 */
public class TokenBindingMessageMakerTest
{
    private static final Logger log = LoggerFactory.getLogger(TokenBindingMessageMakerTest.class);


    @Test
    public void makeEcProvided() throws Exception
    {
        byte[] ekm = new byte[] {89, 9, 12, 43, 71, 44, 2, -10, 35, -19, -21, 57, 43, 39, -107, -17, -92, -8,
                99, 64, 122, 56, -69, 83, 17, 77, 89, -14, -49, -39, 83, -71};

        KeyPair keyPair = EcKeyUtil.generateEcP256KeyPair();
        TokenBindingMessageMaker maker = new TokenBindingMessageMaker().ekm(ekm).providedTokenBinding(TokenBindingKeyParameters.ECDSAP256, keyPair);
        byte[] tbMsg = maker.makeTokenBindingMessage();

        // a few checks for expected content
        assertThat(139, equalTo(tbMsg.length));
        assertThat((byte)0, equalTo(tbMsg[0]));
        assertThat((byte)-119, equalTo(tbMsg[1]));

        assertThat(TokenBindingType.PROVIDED, equalTo(tbMsg[2]));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(tbMsg[3]));

        assertThat((byte)0, equalTo(tbMsg[4]));
        assertThat((byte)65, equalTo(tbMsg[5]));
        assertThat((byte)64, equalTo(tbMsg[6]));

        assertThat((byte)0, equalTo(tbMsg[71]));
        assertThat((byte)64, equalTo(tbMsg[72]));

        assertThat((byte)0, equalTo(tbMsg[137]));
        assertThat((byte)0, equalTo(tbMsg[138]));

        // and then process it
        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBytes(tbMsg, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(64, equalTo(provided.getSignature().length));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());

        assertTrue(provided.getExtensions().length == 0);

        PublicKey publicKey = provided.getTokenBindingID().getPublicKey();
        assertThat(keyPair.getPublic(), equalTo(publicKey));
    }

    @Test
    public void makeEcProvidedAndEcReferred() throws Exception
    {
        byte[] ekm = new byte[] {89, 9, 12, 43, 71, 44, 2, -10, 35, -19, -21, 57, 43, 39, -107, -17, -92, -8,
                99, 64, 122, 56, -69, 83, 17, 77, 89, -14, -49, -39, 83, -71};

        KeyPair keyPairForProvided = EcKeyUtil.generateEcP256KeyPair();
        KeyPair keyPairForReferred = EcKeyUtil.generateEcP256KeyPair();
        TokenBindingMessageMaker maker = new TokenBindingMessageMaker()
                .ekm(ekm)
                .providedTokenBinding(TokenBindingKeyParameters.ECDSAP256, keyPairForProvided)
                .referredTokenBinding(TokenBindingKeyParameters.ECDSAP256, keyPairForReferred);
        byte[] tbMsg = maker.makeTokenBindingMessage();

        // a few checks for expected content
        assertThat(TokenBindingType.PROVIDED, equalTo(tbMsg[2]));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(tbMsg[3]));

        assertThat((byte)0, equalTo(tbMsg[4]));
        assertThat((byte)65, equalTo(tbMsg[5]));
        assertThat((byte)64, equalTo(tbMsg[6]));

        assertThat((byte)0, equalTo(tbMsg[71]));
        assertThat((byte)64, equalTo(tbMsg[72]));

        assertThat((byte)0, equalTo(tbMsg[137]));
        assertThat((byte)0, equalTo(tbMsg[138]));

        assertThat(TokenBindingType.REFERRED, equalTo(tbMsg[139]));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(tbMsg[140]));

        assertThat((byte)0, equalTo(tbMsg[141]));
        assertThat((byte)65, equalTo(tbMsg[142]));
        assertThat((byte)64, equalTo(tbMsg[143]));

        assertThat((byte)0, equalTo(tbMsg[208]));
        assertThat((byte)64, equalTo(tbMsg[209]));

        assertThat((byte)0, equalTo(tbMsg[274]));
        assertThat((byte)0, equalTo(tbMsg[275]));


        // and then process it and check
        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBytes(tbMsg, ekm);
        assertThat(2, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        PublicKey publicKeyProvided = provided.getTokenBindingID().getPublicKey();
        assertThat(keyPairForProvided.getPublic(), equalTo(publicKeyProvided));

        TokenBinding referred = tokenBindingMessage.getReferredTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(referred.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(referred.getKeyParamsIdentifier()));
        PublicKey publicKeyReferred = referred.getTokenBindingID().getPublicKey();
        assertThat(keyPairForReferred.getPublic(), equalTo(publicKeyReferred));
    }

    @Test
    public void makeRsa15Provided() throws Exception
    {
        byte[] ekm = new byte[] {19, 9, 12, 43, 71, 44, 2, -10, 35, -19, -21, 57, 43, 39, -107, -17, -92, -8,
                99, 64, 122, 56, -69, 83, 17, 77, 89, -14, -49, -39, 83, -77};

        KeyPair keyPair = RsaKeyUtil.generate2048RsaKeyPair();
        TokenBindingMessageMaker maker = new TokenBindingMessageMaker()
                .ekm(ekm)
                .providedTokenBinding(TokenBindingKeyParameters.RSA2048_PKCS1_5, keyPair);
        byte[] tbMsg = maker.makeTokenBindingMessage();

        // a few checks for expected content
        assertThat(TokenBindingType.PROVIDED, equalTo(tbMsg[2]));
        assertThat(TokenBindingKeyParameters.RSA2048_PKCS1_5, equalTo(tbMsg[3]));

        assertThat((byte)0, equalTo(tbMsg[tbMsg.length-2]));
        assertThat((byte)0, equalTo(tbMsg[tbMsg.length-1]));

        // and then process it
        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBytes(tbMsg, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.RSA2048_PKCS1_5, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());

        PublicKey publicKey = provided.getTokenBindingID().getPublicKey();
        assertThat(keyPair.getPublic(), equalTo(publicKey));
    }


    @Test
    public void makeRsaPssProvided() throws Exception
    {
        JceProviderTestSupport support = new JceProviderTestSupport();

        support.runWithBouncyCastleProvider(() -> {

            byte[] ekm = new byte[] {19, 9, 12, 43, 71, 44, 2, -10, 35, -19, -21, 57, 43, 39, -107, -17, -92, -8,
                    99, 64, 122, 56, -69, 83, 17, 77, 89, -14, -49, -39, 83, -77};

            KeyPair keyPair = RsaKeyUtil.generate2048RsaKeyPair();
            TokenBindingMessageMaker maker = new TokenBindingMessageMaker()
                    .ekm(ekm)
                    .providedTokenBinding(TokenBindingKeyParameters.RSA2048_PSS, keyPair);
            byte[] tbMsg = maker.makeTokenBindingMessage();

            // a few checks for expected content
            assertThat(TokenBindingType.PROVIDED, equalTo(tbMsg[2]));
            assertThat(TokenBindingKeyParameters.RSA2048_PSS, equalTo(tbMsg[3]));

            assertThat((byte)0, equalTo(tbMsg[tbMsg.length-2]));
            assertThat((byte)0, equalTo(tbMsg[tbMsg.length-1]));

            // and then process it
            TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBytes(tbMsg, ekm);
            assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
            TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
            assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
            assertThat(TokenBindingKeyParameters.RSA2048_PSS, equalTo(provided.getKeyParamsIdentifier()));
            assertNull(tokenBindingMessage.getReferredTokenBinding());

            PublicKey publicKey = provided.getTokenBindingID().getPublicKey();
            assertThat(keyPair.getPublic(), equalTo(publicKey));
        });


    }

    @Test
    public void makeEcProvidedAndRsaReferred() throws Exception
    {
        byte[] ekm = new byte[] {99, 19, 12, 43, 71, 44, 2, -10, 35, -19, -21, 57, 43, 39, -107, -17, -92, -8,
                99, 64, 122, 56, -69, 83, 17, 77, 89, -14, -49, -39, 83, -11};

        KeyPair keyPairForProvided = EcKeyUtil.generateEcP256KeyPair();
        KeyPair keyPairForReferred = RsaKeyUtil.generate2048RsaKeyPair();
        TokenBindingMessageMaker maker = new TokenBindingMessageMaker()
                .ekm(ekm)
                .providedTokenBinding(TokenBindingKeyParameters.ECDSAP256, keyPairForProvided)
                .referredTokenBinding(TokenBindingKeyParameters.RSA2048_PKCS1_5, keyPairForReferred);
        byte[] tbMsg = maker.makeTokenBindingMessage();

        // a few checks for expected content
        assertThat(TokenBindingType.PROVIDED, equalTo(tbMsg[2]));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(tbMsg[3]));

        assertThat((byte)0, equalTo(tbMsg[4]));
        assertThat((byte)65, equalTo(tbMsg[5]));
        assertThat((byte)64, equalTo(tbMsg[6]));

        assertThat((byte)0, equalTo(tbMsg[71]));
        assertThat((byte)64, equalTo(tbMsg[72]));

        assertThat((byte)0, equalTo(tbMsg[137]));
        assertThat((byte)0, equalTo(tbMsg[138]));

        assertThat(TokenBindingType.REFERRED, equalTo(tbMsg[139]));
        assertThat(TokenBindingKeyParameters.RSA2048_PKCS1_5, equalTo(tbMsg[140]));

        assertThat((byte)0, equalTo(tbMsg[tbMsg.length-2]));
        assertThat((byte)0, equalTo(tbMsg[tbMsg.length-1]));


        // and then process it and check
        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBytes(tbMsg, ekm);
        assertThat(2, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        PublicKey publicKeyProvided = provided.getTokenBindingID().getPublicKey();
        assertThat(keyPairForProvided.getPublic(), equalTo(publicKeyProvided));

        TokenBinding referred = tokenBindingMessage.getReferredTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(referred.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.RSA2048_PKCS1_5, equalTo(referred.getKeyParamsIdentifier()));
        PublicKey publicKeyReferred = referred.getTokenBindingID().getPublicKey();
        assertThat(keyPairForReferred.getPublic(), equalTo(publicKeyReferred));
    }


    @Test
    public void makeEcProvidedWithFakeExtension() throws Exception
    {
        byte[] ekm = new byte[] {89, 9, 12, 43, 71, 44, 2, -10, 35, -19, -21, 57, 43, 39, -107, -17, -92, -8,
                99, 64, 122, 56, -69, 83, 17, 77, 89, -14, -49, -39, 83, -71};

        KeyPair keyPair = EcKeyUtil.generateEcP256KeyPair();
        byte[] extensions = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        TokenBindingMessageMaker maker = new TokenBindingMessageMaker()
                .ekm(ekm)
                .tokenBinding(TokenBindingType.PROVIDED, TokenBindingKeyParameters.ECDSAP256, keyPair, extensions);
        byte[] tbMsg = maker.makeTokenBindingMessage();

        // a few checks for expected content

        assertThat(TokenBindingType.PROVIDED, equalTo(tbMsg[2]));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(tbMsg[3]));

        assertThat((byte)0, equalTo(tbMsg[4]));
        assertThat((byte)65, equalTo(tbMsg[5]));
        assertThat((byte)64, equalTo(tbMsg[6]));

        assertThat((byte)0, equalTo(tbMsg[71]));
        assertThat((byte)64, equalTo(tbMsg[72]));

        assertThat((byte)0, equalTo(tbMsg[tbMsg.length - 10]));
        assertThat((byte)1, equalTo(tbMsg[tbMsg.length - 9]));
        assertThat((byte)2, equalTo(tbMsg[tbMsg.length - 8]));
        assertThat((byte)3, equalTo(tbMsg[tbMsg.length - 7]));
        assertThat((byte)4, equalTo(tbMsg[tbMsg.length - 6]));
        assertThat((byte)5, equalTo(tbMsg[tbMsg.length - 5]));
        assertThat((byte)6, equalTo(tbMsg[tbMsg.length - 4]));
        assertThat((byte)7, equalTo(tbMsg[tbMsg.length - 3]));
        assertThat((byte)8, equalTo(tbMsg[tbMsg.length - 2]));
        assertThat((byte)9, equalTo(tbMsg[tbMsg.length - 1]));

        // and then process it
        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBytes(tbMsg, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());

        assertThat(extensions, equalTo(provided.getExtensions()));

        PublicKey publicKey = provided.getTokenBindingID().getPublicKey();
        assertThat(keyPair.getPublic(), equalTo(publicKey));
    }

    @Test
    public void roundTripEncoded() throws Exception
    {
        KeyPair keyPair = EcKeyUtil.generateEcP256KeyPair();
        byte[] ekm = new byte[] {19, 88, 110, 75, 7, -82, -21, -77, 23, 5, -21, 57, 43, 39, -107, -17, -92, -8,
                22, 6, 102, 66, -99, 33, 17, 7, -118, -45, 9, -33, -33, 60};
        byte keyParamsType = TokenBindingKeyParameters.ECDSAP256;
        TokenBindingMessageMaker tbmm = new TokenBindingMessageMaker()
                .ekm(ekm)
                .providedTokenBinding(keyParamsType, keyPair);
        String encodedTokenBindingMessage = tbmm.makeEncodedTokenBindingMessage();

        HttpsTokenBindingServerProcessing httpsTokenBindingServerProcessing = new HttpsTokenBindingServerProcessing();
        TokenBindingMessage tbMessage = httpsTokenBindingServerProcessing.processSecTokenBindingHeader(encodedTokenBindingMessage, keyParamsType, ekm);

        assertThat(1, equalTo(tbMessage.getTokenBindings().size()));
        TokenBinding provided = tbMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tbMessage.getReferredTokenBinding());

        assertTrue(provided.getExtensions().length == 0);

        PublicKey publicKey = provided.getTokenBindingID().getPublicKey();
        assertThat(keyPair.getPublic(), equalTo(publicKey));
    }

    @Test
    public void compareEcEncodingToChrome() throws Exception
    {
        // Take a TB message from Chrome and just ensure that we encode the public key the same way

        String encodedTBM = "AIkAAgBBQGto7hHRR0Y5nkOWqc9KNfwW95dEFmSI_tCZ_Cbl7LWlt6Xjp3DbjiDJavGFiKP2HV_2JSE42VzmKOVVV8" +
                "m7eqAAQOKiDK1Oi0z6v4X5BP7uc0pFestVZ42TTOdJmoHpji06Qq3jsCiCRSJx9ck2fWJYx8tLVXRZPATB3x6c24aY0ZEAAA";

        byte[] ekm = new byte[] {-89, -90, 110, 75, 7, -27, -22, -110, 30, -15, -21, 57, 43, 39, -107, -17, -92, -8,
                -77, 6, 102, 66, -99, 63, 107, 7, 118, -18, 49, -33, -83, -70};

        byte[] tokenBindingMessageFromChromeBytes = Base64.getUrlDecoder().decode(encodedTBM);

        TokenBindingMessage tokenBindingMessage = TokenBindingMessage.fromBytes(tokenBindingMessageFromChromeBytes, ekm);
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        byte[] tbKeyFromChrome = Util.subArray(tokenBindingMessageFromChromeBytes, 6, 65);

        PublicKey publicKey = provided.getTokenBindingID().getPublicKey();
        TokenBindingKeyParameters tokenBindingKeyParameters = TokenBindingKeyParameters.fromIdentifier(TokenBindingKeyParameters.ECDSAP256);
        byte[] tbpk = tokenBindingKeyParameters.encodeTokenBindingPublicKey(publicKey);

        assertThat(tbKeyFromChrome, CoreMatchers.equalTo(tbpk));
    }

    @Test
    public void makeRsa15ProvidedFromStaticKey() throws Exception
    {
        byte[] ekm = new byte[] {49, 4, 12, 43, 71, 44, 2, -10, 35, -19, -21, 57, 43, 39, -107, -17, -92, -8,
                77, 64, 122, 56, -69, 83, 17, 77, 89, -14, -49, -39, 83, -77};

        KeyPair kp = getStaticRsaKeyPair1();

        byte tbKeyParams = TokenBindingKeyParameters.RSA2048_PKCS1_5;

        // make it
        TokenBindingMessageMaker maker = new TokenBindingMessageMaker()
                .ekm(ekm)
                .providedTokenBinding(tbKeyParams, kp);
        String encodedTbMessage = maker.makeEncodedTokenBindingMessage();

        log.debug("Encoded rsa2048_pkcs1.5 Token Binding Message: " + encodedTbMessage);
        log.debug("Encoded EKM: " + Base64.getUrlEncoder().withoutPadding().encodeToString(ekm));

        // and then process it
        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
        TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encodedTbMessage, tbKeyParams, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(tbKeyParams, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());

        assertThat(kp.getPublic(), equalTo(provided.getTokenBindingID().getPublicKey()));
    }

    @Test
    public void makeRsaPssProvidedFromStaticKey() throws Exception
    {
        JceProviderTestSupport support = new JceProviderTestSupport();

        support.runWithBouncyCastleProvider(() -> {
            byte[] ekm = new byte[] {15, 84, 62, 3, 77, 94, 12, -1, -35, -65, -1, 52, 83, 99, -112, -117, -68, 16,
                    72, 31, 121, 14, -84, 83, 8, 7, -59, 13, -6, -38, 27, -41};

            KeyPair kp = getStaticRsaKeyPair2();

            byte tbKeyParams = TokenBindingKeyParameters.RSA2048_PSS;

            // make it
            TokenBindingMessageMaker maker = new TokenBindingMessageMaker()
                    .ekm(ekm)
                    .providedTokenBinding(tbKeyParams, kp);
            String encodedTbMessage = maker.makeEncodedTokenBindingMessage();

            log.debug("Encoded rsa2048_pss Token Binding Message: " + encodedTbMessage);
            log.debug("Encoded EKM: " + Base64.getUrlEncoder().withoutPadding().encodeToString(ekm));

            // and then process it
            HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
            TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encodedTbMessage, tbKeyParams, ekm);
            assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
            TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
            assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
            assertThat(tbKeyParams, equalTo(provided.getKeyParamsIdentifier()));
            assertNull(tokenBindingMessage.getReferredTokenBinding());

            assertThat(kp.getPublic(), equalTo(provided.getTokenBindingID().getPublicKey()));
        });
    }

    @Test
    public void makeEcP256ProvidedFromStaticKey() throws Exception
    {
        byte[] ekm = new byte[] {97, 7, 92, -12, -51, 66, -21, -11, 125, -119, -1, 67, 32, -92, -17, -117, 42, -86,
                39, -49, -101, 56, 73, 82, -17, 69, 9, -4, -43, -94, 3, 22};

        KeyPair kp = getStaticEcKeyPair1();

        byte tbKeyParams = TokenBindingKeyParameters.ECDSAP256;

        // make it
        TokenBindingMessageMaker maker = new TokenBindingMessageMaker()
                .ekm(ekm)
                .providedTokenBinding(tbKeyParams, kp);
        String encodedTbMessage = maker.makeEncodedTokenBindingMessage();

        System.out.println(Arrays.toString(maker.makeTokenBindingMessage()));

        EcdsaP256 ecdsaP256 = new EcdsaP256();
        byte[] a = ecdsaP256.encodeTokenBindingPublicKey(kp.getPublic());
        System.out.println(Arrays.toString(a));

        log.debug("Encoded ecdsap256 Token Binding Message: " + encodedTbMessage);
        log.debug("Encoded EKM: " + Base64.getUrlEncoder().withoutPadding().encodeToString(ekm));

        // and then process it
        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
        TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encodedTbMessage, tbKeyParams, ekm);
        assertThat(1, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(tbKeyParams, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());

        assertThat(kp.getPublic(), equalTo(provided.getTokenBindingID().getPublicKey()));
    }

    @Test
    public void providedAndOthers() throws Exception
    {
        // used in https://tools.ietf.org/html/draft-ietf-tokbind-ttrp for the example with Sec-Other-Token-Binding-ID

        byte[] ekm = Base64.getUrlDecoder().decode("Zr_1DESCcDoaltcZCK613UrEWHRf2B3w9i3bwcxpacc");

        // make it
        KeyPair kp1 = getStaticEcKeyPair1();
        KeyPair kp2 = getStaticEcKeyPair2();
        KeyPair kp3 = getStaticEcKeyPair3();
        byte tbTypeOtherA = (byte) 77;
        byte tbTypeOtherB = (byte) 11;
        TokenBindingMessageMaker maker = new TokenBindingMessageMaker()
                .ekm(ekm)
                .providedTokenBinding(TokenBindingKeyParameters.ECDSAP256, kp1)
                .tokenBinding(tbTypeOtherA, TokenBindingKeyParameters.ECDSAP256, kp2, new byte[0])
                .tokenBinding(tbTypeOtherB, TokenBindingKeyParameters.ECDSAP256, kp3, new byte[0]);
        String encodedTbMessage = maker.makeEncodedTokenBindingMessage();

        Base64.Encoder b64encoder = Base64.getUrlEncoder().withoutPadding();

        log.debug("Encoded EKM :: " + b64encoder.encodeToString(ekm));
        log.debug("Sec-Token-Binding: " + encodedTbMessage);


        // and then process it
        HttpsTokenBindingServerProcessing htbsp = new HttpsTokenBindingServerProcessing();
        TokenBindingMessage tokenBindingMessage = htbsp.processSecTokenBindingHeader(encodedTbMessage, TokenBindingKeyParameters.ECDSAP256, ekm);
        assertThat(3, equalTo(tokenBindingMessage.getTokenBindings().size()));
        TokenBinding provided = tokenBindingMessage.getProvidedTokenBinding();
        assertThat(SignatureResult.Status.VALID, equalTo(provided.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());
        assertThat(kp1.getPublic(), equalTo(provided.getTokenBindingID().getPublicKey()));

        List<TokenBinding> tokenBindings = tokenBindingMessage.getTokenBindings();
        assertThat(provided, equalTo(tokenBindings.get(0)));
        TokenBinding otherTokenBindingA = tokenBindings.get(1);
        assertThat(SignatureResult.Status.VALID, equalTo(otherTokenBindingA.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(otherTokenBindingA.getKeyParamsIdentifier()));
        assertThat(otherTokenBindingA, equalTo(tokenBindingMessage.getTokenBindingByType(tbTypeOtherA)));
        assertThat(tbTypeOtherA, equalTo(otherTokenBindingA.getTokenBindingType().getType()));
        assertThat(kp2.getPublic(), equalTo(otherTokenBindingA.getTokenBindingID().getPublicKey()));

        TokenBinding otherTokenBindingB = tokenBindings.get(2);
        assertThat(SignatureResult.Status.VALID, equalTo(otherTokenBindingB.getSignatureResult().getStatus()));
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(otherTokenBindingB.getKeyParamsIdentifier()));
        assertThat(otherTokenBindingB, equalTo(tokenBindingMessage.getTokenBindingByType(tbTypeOtherB)));
        assertThat(tbTypeOtherB, equalTo(otherTokenBindingB.getTokenBindingType().getType()));
        assertThat(kp3.getPublic(), equalTo(otherTokenBindingB.getTokenBindingID().getPublicKey()));

        String providedID = b64encoder.encodeToString(provided.getOpaqueTokenBindingID());
        log.debug("Sec-Provided-Token-Binding-ID: " + providedID);

        int hexRadix = 16;
        String encodedTokenBindingTypeA = Integer.toString(tbTypeOtherA, hexRadix);
        String encodedTokenBindingTypeB = Integer.toString(tbTypeOtherB, hexRadix);

        String otherA = encodedTokenBindingTypeA + "." + b64encoder.encodeToString(otherTokenBindingA.getOpaqueTokenBindingID());
        String otherB = encodedTokenBindingTypeB + "." + b64encoder.encodeToString(otherTokenBindingB.getOpaqueTokenBindingID());

        log.debug("Sec-Other-Token-Binding-ID: " + otherA + "," + otherB);
    }

    private KeyPair getStaticRsaKeyPair1() throws GeneralSecurityException
    {

        String modulusString = "tjbp00bntpjy4y9sap11ixfqph9uytnrhmmzzk6tk7cviytswf8yiofau2inxwuv6do5rqsexhx94qusytd7a5tpk888rw78laisu8h9s247l89kzh" +
                "4ig1z1ekkrm90w3hz00m6vbdkrylljzjbdov04crgi9mqnt8dnrmxnbyj1yfpywsj6k4mp92upid7r89u1p3m8x0qqjkv42jjgu0bgubp8h0othwdgzp0hvvqps464542" +
                "2pp7ubsvbvfq5rn4ckah227o3wxwm5ytuwtsh1rwqwxtflbr0gzsu3n9t3odr64lmi8i2ydg53yhvw9s3o4f9q8rtipwes28tlo376tduzg904redv8vbjn7ztiu8iv0g" +
                "a3zunn1g086on5cqujl9c9i7";
        String privateExponentString = "s4tzwohopskm1cgsv5rbivkm6c9b4j1cqnsvsm9rhengva682hj27opnkyhcdfpk5ysggl8zjen0dgp8cmw8n44shyzzu801z7fldyrmlj" +
                "j8m6r0fvw4z1fy05l4nyk0jn8c29vwhm4ssvgozo79iqlvnmvq8himgurmjvsddmvx9ijqcgn4cc3mxgzl6hualb3dzdxu64w0klcpaxi58o22qqdol5blcqcfboi5dqa" +
                "92a0a6wej4rklqtpj2cvtnxt41tmcwkqgrej8kek0fi6ola1w6e75414wpdlurhkvxfejaqzckcjpxv2m9uoxtzeu31iddezysf6t91xrz56um5104mznt84bh3npr95a" +
                "8czzhwymgmru187eg976b6xv40djj4e1";
        String publicExponentString = "1ekh";

        return rsaKeyPair(modulusString, privateExponentString, publicExponentString);
    }

    private KeyPair rsaKeyPair(String modulusString, String privateExponentString, String publicExponentString) throws GeneralSecurityException
    {
        int radix = Character.MAX_RADIX;
        KeyFactory kf = KeyFactory.getInstance("RSA");
        BigInteger modulus = new BigInteger(modulusString, radix);
        BigInteger publicExponent = new BigInteger(publicExponentString, radix);
        PublicKey publicKey = kf.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
        BigInteger privateExponent = new BigInteger(privateExponentString, radix);
        PrivateKey privateKey = kf.generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent));

        return new KeyPair(publicKey, privateKey);
    }


    private KeyPair getStaticRsaKeyPair2() throws GeneralSecurityException
    {

//        KeyPair keyPair = RsaKeyUtil.generate2048RsaKeyPair();
//        RSAPrivateKey  aPrivate = (RSAPrivateKey)keyPair.getPrivate();
//        RSAPublicKey aPublic = (RSAPublicKey) keyPair.getPublic();
//        System.out.println("m " +  aPrivate.getModulus().toString(radix));
//        System.out.println("prix " +  aPrivate.getPrivateExponent().toString(radix));
//        System.out.println("pubx " +  aPublic.getPublicExponent().toString(radix));

        String modulusString = "xytp7tfszvddrco02584y2iwybcf7motd2q6k2zdnyvwaxllfd3y2t3017mzyiw1um4mjpxki0il8sbnyorc786ws2pzg6m4edtm4plf6mwipt5l1i" +
                "ksvx4c9hv7qczfinx9rswf0o5pudz2jw20sgtt8ixv9g1x3o4ocpe7vyq57j7t89as3cxnqaj4bn5i3ejpoeoqqlc6mfoi357h1vldsv1zt6woqqvm1wsm7zqej37lht4" +
                "7ut6drjfdy4sxk16o636nlyr534dp44e2hdc7aej1go297bvnyeen55xntufwa4q4m3jnvtymefbi24f6advtn3dw3lbt77rug76b4owdfv0vvusilppplgmolfsmbt2u" +
                "7bcc3lgtt1favwckxkyb26gv";
        String privateExponentString = "f46co3mddeo0up3utbtupe5jkkvh3c57tqopb4s2ldr0qpeyqg923hzd9foe3jkd4g53e60uo3t8uuhadl4uvl0j0hzxj666phxu84iuws" +
                "insiw49umpliu91lqzoaori2xmxqvuyoow1ymnts59vqvft1nk0mdiynqjvoo3wbvm9189jtrphj8b3yv7tesel5djsucoaziepgwo2hdz1sbvqourakuy48e7fjuee1x" +
                "uqw4gqbxlyrgxopbvakipxku6lf88dmibtguxaqphhkbz2cfc3k5unf2zgxpfw1b5gc4j6zr7na21yvhx1vli7y1qmhwkwcs7jl4p3gzet1sshr6yrdcp0ms254g2tht2" +
                "al6vye83fo9pnipe3l6h77z8tkz2fvtl";
        String publicExponentString = "1ekh";

        return rsaKeyPair(modulusString, privateExponentString, publicExponentString);
    }

    private KeyPair getStaticEcKeyPair1() throws GeneralSecurityException
    {
//        int radix = Character.MAX_RADIX;
//        KeyPair keyPair = EcKeyUtil.generateEcP256KeyPair();
//        ECPrivateKey  aPrivate = (ECPrivateKey)keyPair.getPrivate();
//        ECPublicKey aPublic = (ECPublicKey) keyPair.getPublic();
//        String s = aPrivate.getS().toString(radix);
//        String x = aPublic.getW().getAffineX().toString(radix);
//        String y = aPublic.getW().getAffineY().toString(radix);
//        System.out.println("s " + s);
//        System.out.println("x " + x);
//        System.out.println("y " + y);

        String s = "11bcdq19flcnx1m6py6a7uh90olznz5pzxoqx7jzm2trtyzkei";
        String x = "cjeheyvv38uegvzxh1voizouhh4y60pxx0ncusn79ql0tb75z";
        String y = "390i77mdovfg1wje78yb8ajvot22cqzo5m0wyfhfodp45q4uuj";


        return ecKeyPair(s, x, y);
    }

    private KeyPair getStaticEcKeyPair2() throws GeneralSecurityException
    {
        String s = "2a87olfjrcxhh4ptl1rwvt5d9tb2o3owfrlz3dh5923yltgx15";
        String x = "1sbhf1nu3joimzfr0pwh1qrslh2y8f5e2y4t8htxo5frgh0yon";
        String y = "4bujmrt2d9kqus2g9ns5zl0ykf9qs3rfvl1lavic3hafjb417r";

        return ecKeyPair(s, x, y);
    }

    private KeyPair getStaticEcKeyPair3() throws GeneralSecurityException
    {
        String s = "4p9vr9990rlt5hl91t5u53qioya7u5rdexzr0x7utd0dh9y58n";
        String x = "3a51kn8tah9mitsugnqac3ndfjzp2dzuvqjtxz6eh828b9nk6i";
        String y = "1geahejyse4ecehzvx9s7dbgnahpcwkzqvpv44ilyssz6fazkx";

        return ecKeyPair(s, x, y);
    }

    private KeyPair ecKeyPair(String s, String x, String y) throws GeneralSecurityException
    {
        int radix = Character.MAX_RADIX;

        KeyFactory kf = KeyFactory.getInstance("EC");
        BigInteger si = new BigInteger(s, radix);
        BigInteger xi = new BigInteger(x, radix);
        BigInteger yi = new BigInteger(y, radix);

        AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
        algorithmParameters.init(new ECGenParameterSpec(EcKeyUtil.P256_CURVE_NAME));
        ECParameterSpec ecParameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(xi, yi);
        PublicKey publicKey = kf.generatePublic(new ECPublicKeySpec(point, ecParameterSpec));

        PrivateKey privateKey = kf.generatePrivate(new ECPrivateKeySpec(si, ecParameterSpec));

        return new KeyPair(publicKey, privateKey);
    }
}
