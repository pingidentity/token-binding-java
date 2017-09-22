package b_c.unbearable.client;

import b_c.unbearable.messages.SignatureResult;
import b_c.unbearable.messages.TokenBinding;
import b_c.unbearable.messages.TokenBindingKeyParameters;
import b_c.unbearable.messages.TokenBindingMessage;
import b_c.unbearable.messages.TokenBindingType;
import b_c.unbearable.utils.EcKeyUtil;
import b_c.unbearable.utils.RsaKeyUtil;
import b_c.unbearable.utils.Util;
import org.hamcrest.CoreMatchers;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class TokenBindingMessageMakerTest
{
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
        assertThat(TokenBindingKeyParameters.ECDSAP256, equalTo(provided.getKeyParamsIdentifier()));
        assertNull(tokenBindingMessage.getReferredTokenBinding());

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
}
