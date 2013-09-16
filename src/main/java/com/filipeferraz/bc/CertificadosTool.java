package com.filipeferraz.bc;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class CertificadosTool {

    public static final String PROVEDOR_PADRAO = "BC";
    public static final String CRIPTOGRAFIA_PADRAO = "SHA256WithRSAEncryption";

    public static X509Certificate gerarCertificadoX509v3(KeyPair keyPair, X500NameBuilder builderEmissor, X500NameBuilder builderSubject) throws OperatorCreationException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Calendar calendar = Calendar.getInstance();
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.YEAR, 10);
        Date notAfter = calendar.getTime();
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builderEmissor.build(),
                serial, notBefore, notAfter, builderSubject.build(), keyPair.getPublic());
        ContentSigner sigGen = new JcaContentSignerBuilder(CRIPTOGRAFIA_PADRAO)
                .setProvider(PROVEDOR_PADRAO).build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(PROVEDOR_PADRAO)
                .getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());
        cert.verify(cert.getPublicKey());
        return cert;
    }

    public static X509Certificate gerarCertificadoX509v3(KeyPair keyPair) throws CertificateException, NoSuchAlgorithmException, OperatorCreationException, SignatureException, NoSuchProviderException, InvalidKeyException {
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
        builderSubject.addRDN(BCStyle.CN, "Pessoa");

        return gerarCertificadoX509v3(keyPair, builderEmissor, builderSubject);
    }

}
