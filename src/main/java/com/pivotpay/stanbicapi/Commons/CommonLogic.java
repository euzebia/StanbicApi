package com.pivotpay.stanbicapi.Commons;

import com.pivotpay.stanbicapi.Models.StatusCodes;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;


@Slf4j
@Service
public class CommonLogic {
    @Value("${access_key}")
    private  String accessCode;
    public String generateToken(String serviceID,String clientID,String requestReference,
                                String customerID,String amount)
    {
        try
        {
            String dataToEncode = serviceID+clientID+requestReference+customerID+amount;

        }
        catch(Exception exception)
        {

        }
        return null;
    }


   @Scheduled(fixedDelay = 1000)
    public String encryptData(){
        try
        {
            String nonce = generateNonce();
            System.out.println("Nonce:"+nonce);
//           String dataToEncrypt="Hello,PivotPayments!";
//           String privateKeyPath="C:/certificates/PivotPaytsPrvt.pem";
//            String base64Signature = signSHA1withRSA(dataToEncrypt,privateKeyPath);
//            System.out.println("Signature="+base64Signature);
        //return base64Signature;
            return "";
        }
        catch(Exception exception)
        {
           log.info("Exception while encrypting request: "+exception.getMessage());
            return "";
        }
    }



    // Create base64 encoded signature using SHA1/RSA.
    private static String signSHA1withRSA(String input, String strPk) throws Exception {
       try
      {
          PrivateKey privateKey= loadKey(strPk,"FbhQ;\\B569bMeCMb");
           Signature signature = Signature.getInstance("SHA1withRSA");
           signature.initSign(privateKey);
           signature.update(input.getBytes("UTF-8"));
           byte[] s = signature.sign();
           //log.info("Signature:"+Base64.getEncoder().encodeToString(s));
           //boolean signatureStatus = verify(input,Base64.getEncoder().encodeToString(s),getPublicKey("C:/certificates/publicCert.pem"));
           return Base64.getEncoder().encodeToString(s);

       }
       catch (Exception exception)
       {
           log.info("Exception: error encountered -"+exception.getMessage());
           return null;
       }
    }

    public static PrivateKey loadKey(String path, String passphrase) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        try {
            File file = ResourceUtils.getFile(path);
            PEMParser pemParser = new PEMParser(new FileReader(file));
            Object o = pemParser.readObject();
            PrivateKeyInfo pki;

            if (o instanceof PKCS8EncryptedPrivateKeyInfo) {

                PKCS8EncryptedPrivateKeyInfo privateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) o;

                JcePKCSPBEInputDecryptorProviderBuilder builder =
                        new JcePKCSPBEInputDecryptorProviderBuilder().setProvider("BC");

                InputDecryptorProvider idp = builder.build(passphrase.toCharArray());

                pki = privateKeyInfo.decryptPrivateKeyInfo(idp);
            } else if (o instanceof PEMEncryptedKeyPair) {

                PEMEncryptedKeyPair privateKeyInfo = (PEMEncryptedKeyPair) o;
                PEMKeyPair pkp = privateKeyInfo.decryptKeyPair(new BcPEMDecryptorProvider(passphrase.toCharArray()));

                pki = pkp.getPrivateKeyInfo();
            } else {
                throw new PKCSException("Invalid encrypted private key class: " + o.getClass().getName());
            }

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return converter.getPrivateKey(pki);
        } catch (Exception e) {
            System.out.println("Error happened while loading key");
            e.printStackTrace();
            return null;
        }
    }


    private static PublicKey getPublicKey( String keyPath )
            throws NoSuchAlgorithmException, IOException, InvalidKeySpecException
    {
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final PemReader reader = new PemReader( new FileReader( keyPath));
        final byte[] pubKey = reader.readPemObject().getContent();
        final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec( pubKey );

        return keyFactory.generatePublic( publicKeySpec );
    }

    private static boolean verify( String message, String sign, PublicKey publicKey )
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException
    {
        final Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify( publicKey );
        sig.update( message.getBytes("UTF-8"));

        final byte[] bytes = Base64.getDecoder(). decode(sign);

        return sig.verify( bytes );
    }

    public String generateNonce(){
        try
        {
            int leftLimit = 48; // numeral '0'
            int rightLimit = 122; // letter 'z'
            int targetStringLength = 20;
            Random random = new Random();

            String generatedString = random.ints(leftLimit, rightLimit + 1)
                    .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                    .limit(targetStringLength)
                    .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                    .toString();
             return generatedString;
        }
        catch(Exception exception){
            log.info("Exception on generating nonce:"+exception.getMessage());
            return null;

        }
    }

}

