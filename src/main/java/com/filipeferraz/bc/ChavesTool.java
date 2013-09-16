package com.filipeferraz.bc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class ChavesTool {

    public static String ALGORITMO_PADRAO = "RSA";
    public static Integer TAMANHO_PADRAO = 2048;

    public static KeyPair gerarChaves() throws NoSuchAlgorithmException {
        return ChavesTool.gerarChaves(ALGORITMO_PADRAO, TAMANHO_PADRAO);
    }

    public static KeyPair gerarChaves(Integer tamanho) throws NoSuchAlgorithmException {
        return ChavesTool.gerarChaves(ALGORITMO_PADRAO, tamanho);
    }

    public static KeyPair gerarChaves(String algoritmo, Integer tamanho) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algoritmo);
        keyPairGenerator.initialize(tamanho);
        return keyPairGenerator.generateKeyPair();
    }

}
