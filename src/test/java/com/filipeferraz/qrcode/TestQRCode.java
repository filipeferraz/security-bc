package com.filipeferraz.qrcode;

import com.filipeferraz.bc.ChavesTool;
import com.filipeferraz.bc.CriptografiaTool;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import net.glxn.qrgen.QRCode;
import net.glxn.qrgen.image.ImageType;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.imageio.ImageIO;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class TestQRCode {

    @Test
    public void testGerarQRCode() throws FileNotFoundException {
        File imagem = new File("target/qrcode.png");
        FileOutputStream fos = new FileOutputStream(imagem);

        QRCode.from("http://www.filipeferraz.com").to(ImageType.PNG).withSize(400, 400).writeTo(fos);

        Assert.assertTrue(imagem.exists());
    }

    @Test
    public void testGerarQRCodeCriptografado() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, ShortBufferException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String textoEntrada = "http://www.filipeferraz.com";

        KeyPair keyPairServidor = ChavesTool.gerarChaves();

        String textoCriptografado = CriptografiaTool.criptografar(keyPairServidor.getPublic(), textoEntrada);
        System.out.println("Texto criptografado: " + textoCriptografado);

        File imagem = new File("target/qrcode.png");
        FileOutputStream fos = new FileOutputStream(imagem);

        QRCode.from(textoCriptografado).to(ImageType.PNG).withSize(400, 400).writeTo(fos);

        Assert.assertTrue(imagem.exists());

        String textoDescriptografado = CriptografiaTool.descriptografar(keyPairServidor.getPrivate(), textoCriptografado);
        System.out.println("Texto descriptografado: " + textoDescriptografado);
    }

    @Test
    public void testGerarQRCodeDescriptografado() throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IOException, NotFoundException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String textoEntrada = "Texto de teste";

        KeyPair keyPairServidor = ChavesTool.gerarChaves();

        String textoCriptografado = CriptografiaTool.criptografar(keyPairServidor.getPublic(), textoEntrada);

        File imagem = new File("target/qrcode.png");
        FileOutputStream fos = new FileOutputStream(imagem);

        QRCode.from(textoCriptografado).to(ImageType.PNG).withSize(400, 400).writeTo(fos);

        Assert.assertTrue(imagem.exists());

        Result resultado = carregarImagemQRCode(imagem.getAbsolutePath());

        String textoDescriptografado = CriptografiaTool.descriptografar(keyPairServidor.getPrivate(), resultado.getText());
        System.out.println("Texto descriptografado: " + textoDescriptografado);

        Assert.assertEquals(textoEntrada, textoDescriptografado);
    }

    private Result carregarImagemQRCode(String caminho) throws IOException, NotFoundException {
        Result result = null;
        BinaryBitmap binaryBitmap;
        binaryBitmap = new BinaryBitmap(
                new HybridBinarizer(
                        new BufferedImageLuminanceSource(
                                ImageIO.read(new FileInputStream(
                                        caminho)))));
        result = new MultiFormatReader().decode(binaryBitmap);
        return result;
    }

}
