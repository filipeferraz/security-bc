package com.filipeferraz.bc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class AssinaturaTool {

    public static final String PROVEDOR_PADRAO = "BC";
    public static final String CRIPTOGRAFIA_PADRAO = "SHA256WithRSAEncryption";

    public static byte[] gerarAssinatura(PrivateKey privateKey, String conteudo) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return gerarAssinatura(privateKey, conteudo.getBytes(), CRIPTOGRAFIA_PADRAO, PROVEDOR_PADRAO);
    }

    public static byte[] gerarAssinatura(PrivateKey privateKey, String conteudo, String criptografia) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return gerarAssinatura(privateKey, conteudo.getBytes(), criptografia, PROVEDOR_PADRAO);
    }

    public static byte[] gerarAssinatura(PrivateKey privateKey, String conteudo, String criptografia, String provedor) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return gerarAssinatura(privateKey, conteudo.getBytes(), criptografia, provedor);
    }

    public static byte[] gerarAssinatura(PrivateKey privateKey, byte[] conteudo) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return gerarAssinatura(privateKey, conteudo, CRIPTOGRAFIA_PADRAO, PROVEDOR_PADRAO);
    }

    public static byte[] gerarAssinatura(PrivateKey privateKey, byte[] conteudo, String criptografia) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return gerarAssinatura(privateKey, conteudo, criptografia, PROVEDOR_PADRAO);
    }

    public static byte[] gerarAssinatura(PrivateKey privateKey, byte[] conteudo, String criptografia, String provedor) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        Signature signer = Signature.getInstance(criptografia, provedor);
        signer.initSign(privateKey);
        signer.update(conteudo, 0, conteudo.length);
        return signer.sign();
    }

    public static boolean verificarAssinatura(PublicKey publicKey, byte[] conteudo, byte[] assinatura) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo, assinatura, CRIPTOGRAFIA_PADRAO, PROVEDOR_PADRAO);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, byte[] conteudo, byte[] assinatura, String criptografia) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo, assinatura, criptografia, PROVEDOR_PADRAO);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, byte[] conteudo, byte[] assinatura, String criptografia, String provedor) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        Signature signerVerificador = Signature.getInstance(criptografia, provedor);
        signerVerificador.initVerify(publicKey);
        signerVerificador.update(conteudo, 0, conteudo.length);
        return signerVerificador.verify(assinatura);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, String conteudo, String assinatura) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo.getBytes(), assinatura.getBytes(), CRIPTOGRAFIA_PADRAO, PROVEDOR_PADRAO);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, String conteudo, String assinatura, String criptografia) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo.getBytes(), assinatura.getBytes(), criptografia, PROVEDOR_PADRAO);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, String conteudo, String assinatura, String criptografia, String provedor) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo.getBytes(), assinatura.getBytes(), criptografia, provedor);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, byte[] conteudo, String assinatura) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo, assinatura.getBytes(), CRIPTOGRAFIA_PADRAO, PROVEDOR_PADRAO);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, byte[] conteudo, String assinatura, String criptografia) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo, assinatura.getBytes(), criptografia, PROVEDOR_PADRAO);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, byte[] conteudo, String assinatura, String criptografia, String provedor) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo, assinatura.getBytes(), criptografia, provedor);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, String conteudo, byte[] assinatura) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo.getBytes(), assinatura, CRIPTOGRAFIA_PADRAO, PROVEDOR_PADRAO);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, String conteudo, byte[] assinatura, String criptografia) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo.getBytes(), assinatura, criptografia, PROVEDOR_PADRAO);
    }

    public static boolean verificarAssinatura(PublicKey publicKey, String conteudo, byte[] assinatura, String criptografia, String provedor) throws InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchAlgorithmException {
        return verificarAssinatura(publicKey, conteudo.getBytes(), assinatura, criptografia, provedor);
    }

}
