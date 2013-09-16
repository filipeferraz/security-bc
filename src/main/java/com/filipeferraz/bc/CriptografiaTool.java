package com.filipeferraz.bc;

import org.bouncycastle.util.encoders.Base64Encoder;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class CriptografiaTool {

    public static final String CRIPTOGRAFIA_PADRAO = "RSA";

    public static String criptografar(PublicKey publicKey, String texto) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        byte[] mensagem = texto.getBytes("UTF-8");
        Cipher cipher = Cipher.getInstance(CRIPTOGRAFIA_PADRAO);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(mensagem);

        return new BASE64Encoder().encode(cipherText);
    }

    public static String descriptografar(PrivateKey privateKey, String texto) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] mensagem = new BASE64Decoder().decodeBuffer(texto);
        Cipher cipher = Cipher.getInstance(CRIPTOGRAFIA_PADRAO);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cipherData = cipher.doFinal(mensagem);
        return new String(cipherData);
    }


}
