package com.filipeferraz.bc;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TestPrincipal {

    @Test
    public void testGerarChaves() throws NoSuchAlgorithmException {
        KeyPair keyPair = ChavesTool.gerarChaves();
        Assert.assertNotNull(keyPair);
        Assert.assertEquals(ChavesTool.ALGORITMO_PADRAO, keyPair.getPrivate().getAlgorithm());
    }

    @Test
    public void testGerarCertificadoX509v3() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, SignatureException, InvalidKeyException, NoSuchProviderException {
        KeyPair keyPair = ChavesTool.gerarChaves();
        X509Certificate certificado = CertificadosTool.gerarCertificadoX509v3(keyPair);
    }

    @Test
    public void testGerarKeyStore() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPair keyPairServidor = ChavesTool.gerarChaves();

        File arquivoKeyStore = new File("target/keystoreTest.jks");

        KeyStoreTool.criarKeyStore(arquivoKeyStore.getAbsolutePath(), keyPairServidor.getPrivate(), "changeit".toCharArray());
        Assert.assertTrue(arquivoKeyStore.exists());

        arquivoKeyStore.delete();
    }

    @Test
    public void testAssinatura() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException, KeyStoreException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPair keyPairServidor = ChavesTool.gerarChaves();
        KeyPair keyPairSubject = ChavesTool.gerarChaves();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        X500NameBuilder builderEmissor = new X500NameBuilder(BCStyle.INSTANCE);
        builderEmissor.addRDN(BCStyle.DC, "com");
        builderEmissor.addRDN(BCStyle.DC, "empresa");
        builderEmissor.addRDN(BCStyle.OU, "emissao");
        builderEmissor.addRDN(BCStyle.O, "Orgão emissor");
        builderEmissor.addRDN(BCStyle.CN, "Empresa Emissora");

        X500NameBuilder builderSubject1 = new X500NameBuilder(BCStyle.INSTANCE);
        builderSubject1.addRDN(BCStyle.DC, "com");
        builderSubject1.addRDN(BCStyle.DC, "empresa");
        builderSubject1.addRDN(BCStyle.OU, "emissao");
        builderSubject1.addRDN(BCStyle.O, "Orgão emissor");
        builderSubject1.addRDN(BCStyle.CN, "Subject 1");

        X509Certificate certificadoSubject = CertificadosTool.gerarCertificadoX509v3(keyPairSubject, builderEmissor, builderSubject1);

        File arquivoKeyStore = new File("target/keystoreTest.jks");
        String senha = "changeit";

        KeyStoreTool.criarKeyStore(arquivoKeyStore.getAbsolutePath(), keyPairServidor.getPrivate(), senha.toCharArray());
        KeyStoreTool.adicionarCertificado(arquivoKeyStore.getAbsolutePath(), keyPairServidor.getPrivate(), senha.toCharArray(), certificadoSubject, "empresa");

        String texto = "texto de teste";

        byte[] assinatura = AssinaturaTool.gerarAssinatura(keyPairSubject.getPrivate(), texto);
        boolean verificacao = AssinaturaTool.verificarAssinatura(keyPairSubject.getPublic(), texto, assinatura);
        Assert.assertTrue(verificacao);

        arquivoKeyStore.delete();
    }

    @Test
    public void testCriarArquivoPKCS12() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException, KeyStoreException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPair keyPairSubject = ChavesTool.gerarChaves();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        X500NameBuilder builderEmissor = new X500NameBuilder(BCStyle.INSTANCE);
        builderEmissor.addRDN(BCStyle.DC, "com");
        builderEmissor.addRDN(BCStyle.DC, "empresa");
        builderEmissor.addRDN(BCStyle.OU, "emissao");
        builderEmissor.addRDN(BCStyle.O, "Orgão emissor");
        builderEmissor.addRDN(BCStyle.CN, "Empresa Emissora");

        X500NameBuilder builderSubject = new X500NameBuilder(BCStyle.INSTANCE);
        builderSubject.addRDN(BCStyle.DC, "com");
        builderSubject.addRDN(BCStyle.DC, "empresa");
        builderSubject.addRDN(BCStyle.OU, "emissao");
        builderSubject.addRDN(BCStyle.O, "Orgão emissor");
        builderSubject.addRDN(BCStyle.CN, "Subject 1");
        X509Certificate certificadoPessoa1 = CertificadosTool.gerarCertificadoX509v3(keyPairSubject, builderEmissor, builderSubject);

        File arquivoPKCS12 = new File("target/id.p12");
        String password = "123456";

        KeyStoreTool.criarArquivoPKCS12(keyPairSubject.getPrivate(), certificadoPessoa1, arquivoPKCS12.getAbsolutePath(), password.toCharArray());

        Assert.assertTrue(arquivoPKCS12.exists());

        arquivoPKCS12.delete();
    }

    @Test
    public void testCriarArquivoCert() throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPair keyPairSubject = ChavesTool.gerarChaves();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        X500NameBuilder builderEmissor = new X500NameBuilder(BCStyle.INSTANCE);
        builderEmissor.addRDN(BCStyle.DC, "com");
        builderEmissor.addRDN(BCStyle.DC, "empresa");
        builderEmissor.addRDN(BCStyle.OU, "emissao");
        builderEmissor.addRDN(BCStyle.O, "Orgão emissor");
        builderEmissor.addRDN(BCStyle.CN, "Empresa Emissora");

        X500NameBuilder builderSubject = new X500NameBuilder(BCStyle.INSTANCE);
        builderSubject.addRDN(BCStyle.DC, "com");
        builderSubject.addRDN(BCStyle.DC, "empresa");
        builderSubject.addRDN(BCStyle.OU, "emissao");
        builderSubject.addRDN(BCStyle.O, "Orgão emissor");
        builderSubject.addRDN(BCStyle.CN, "Subject 1");
        X509Certificate certificadoSubject = CertificadosTool.gerarCertificadoX509v3(keyPairSubject, builderEmissor, builderSubject);

        File arquivoCert = new File("target/id.cert");

        KeyStoreTool.criarArquivoCert(certificadoSubject, arquivoCert.getAbsolutePath());

        Assert.assertTrue(arquivoCert.exists());

        arquivoCert.delete();
    }

    @Test
    public void testCertificadoKeyStore() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPair keyPairServidor = ChavesTool.gerarChaves();
        KeyPair keyPairSubject1 = ChavesTool.gerarChaves();
        KeyPair keyPairSubject2 = ChavesTool.gerarChaves();

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        X500NameBuilder builderEmissor = new X500NameBuilder(BCStyle.INSTANCE);
        builderEmissor.addRDN(BCStyle.DC, "com");
        builderEmissor.addRDN(BCStyle.DC, "empresa");
        builderEmissor.addRDN(BCStyle.OU, "emissao");
        builderEmissor.addRDN(BCStyle.O, "Orgão emissor");
        builderEmissor.addRDN(BCStyle.CN, "Empresa Emissora");

        X500NameBuilder builderSubject1 = new X500NameBuilder(BCStyle.INSTANCE);
        builderSubject1.addRDN(BCStyle.DC, "com");
        builderSubject1.addRDN(BCStyle.DC, "empresa");
        builderSubject1.addRDN(BCStyle.OU, "emissao");
        builderSubject1.addRDN(BCStyle.O, "Orgão emissor");
        builderSubject1.addRDN(BCStyle.CN, "Subject 1");

        X500NameBuilder builderSubject2 = new X500NameBuilder(BCStyle.INSTANCE);
        builderSubject2.addRDN(BCStyle.DC, "com");
        builderSubject2.addRDN(BCStyle.DC, "empresa");
        builderSubject2.addRDN(BCStyle.OU, "emissao");
        builderSubject2.addRDN(BCStyle.O, "Orgão emissor");
        builderSubject2.addRDN(BCStyle.CN, "Subject 2");

        X509Certificate certificadoSubject1 = CertificadosTool.gerarCertificadoX509v3(keyPairSubject1, builderEmissor, builderSubject1);
        X509Certificate certificadoSubject2 = CertificadosTool.gerarCertificadoX509v3(keyPairSubject2, builderEmissor, builderSubject2);

        File arquivoKeyStore = new File("target/keystoreTest.jks");
        String password = "changeit";
        String alias = "empresa";

        KeyStoreTool.criarKeyStore(arquivoKeyStore.getAbsolutePath(), keyPairServidor.getPrivate(), password.toCharArray());
        KeyStoreTool.adicionarCertificado("target/keystoreTest.jks", keyPairServidor.getPrivate(), password.toCharArray(), certificadoSubject1, alias);

        boolean presente1 = KeyStoreTool.isCertificadoPresente(arquivoKeyStore.getAbsolutePath(), password.toCharArray(), certificadoSubject1, alias);
        Assert.assertTrue(presente1);

        boolean presente2 = KeyStoreTool.isCertificadoPresente(arquivoKeyStore.getAbsolutePath(), password.toCharArray(), certificadoSubject2, alias);
        Assert.assertFalse(presente2);

        arquivoKeyStore.delete();
    }

}
