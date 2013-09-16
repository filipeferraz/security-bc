package com.filipeferraz.bc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class KeyStoreTool {

    public static String ALIAS_PADRAO = "alias";

    private static KeyStore carregarKeyStore(String caminho, char[] password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore store = KeyStore.getInstance("JKS");
        File keystore = new File(caminho);
        if (keystore.exists()) {
            FileInputStream fis = new FileInputStream(keystore);
            store.load(fis, password);
            fis.close();
        } else {
            store.load(null);
        }
        return store;
    }

    private static void salvarKeyStore(String caminho, char[] password, KeyStore keyStore) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        FileOutputStream fos = new FileOutputStream(new File(caminho));
        keyStore.store(fos, password);
        fos.close();
    }

    public static KeyStore carregarKeystore(String caminho, char[] password) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore store = carregarKeyStore(caminho, password);
        return store;
    }

    public static void criarKeyStore(String caminho, PrivateKey privateKey, char[] password) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore store = carregarKeyStore(caminho, password);
        salvarKeyStore(caminho, password, store);
    }

    public static void adicionarCertificado(String caminho, PrivateKey privateKey, char[] password, X509Certificate certificado) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        adicionarCertificado(caminho, privateKey, password, certificado, ALIAS_PADRAO);
    }

    public static void adicionarCertificado(String caminho, PrivateKey privateKey, char[] password, X509Certificate certificado, String alias) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore store = carregarKeyStore(caminho, password);

        Certificate[] arrayCert = store.getCertificateChain(alias);
        List<Certificate> listaCertificados = null;
        if (arrayCert == null) {
            listaCertificados = new ArrayList<Certificate>();
        } else {
            listaCertificados = new ArrayList<Certificate>(Arrays.asList(arrayCert));
        }
        listaCertificados.add(certificado);

        Certificate[] arrayCertFinal = new Certificate[listaCertificados.size()];
        for (int i=0; i < listaCertificados.size(); i++) {
            arrayCertFinal[i] = listaCertificados.get(i);
        }

        store.setKeyEntry(alias, privateKey, password,
                arrayCertFinal);

        salvarKeyStore(caminho, password, store);
    }

    public static void criarArquivoPKCS12(PrivateKey privateKey, Certificate certificado, String arquivo, char[] password) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        File keystore = new File(arquivo);
        if (keystore.exists()) {
            FileInputStream fis = new FileInputStream(keystore);
            store.load(fis, null);
            fis.close();
        } else {
            store.load(null);
        }

        store.setKeyEntry(ALIAS_PADRAO, privateKey, password, new Certificate[] {certificado});

        FileOutputStream fOut = new FileOutputStream(arquivo);
        store.store(fOut, password);
    }

    public static void criarArquivoCert(Certificate certificado, String caminho) throws IOException, CertificateEncodingException {
        FileOutputStream fos = new FileOutputStream(caminho);
        fos.write(certificado.getEncoded());
        fos.close();
    }

    public static boolean isCertificadoPresente(String caminho, char[] password, Certificate certificado) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        return isCertificadoPresente(caminho, password, certificado, ALIAS_PADRAO);
    }

    public static boolean isCertificadoPresente(String caminho, char[] password, Certificate certificado, String alias) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore store = carregarKeystore(caminho, password);

        Certificate[] certificados = store.getCertificateChain(alias);

        if (certificados == null) {
            return false;
        }

        for (int i=0; i<certificados.length; i++) {
            if (certificados[i].equals(certificado)) {
                return true;
            }
        }

        return false;
    }

}
