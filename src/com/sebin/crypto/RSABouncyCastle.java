package com.sebin.crypto;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

public class RSABouncyCastle {
	public static XYSeriesCollection getDataset() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidCipherTextException {
		Security.addProvider(new BouncyCastleProvider());
				
				PrivateKey pvk;
				PublicKey pbk;
				int[] keysizes=new int[] {128,256,512,1024,2048,3072,4096};
				ArrayList<Double> dec_time=new ArrayList<>();
				ArrayList<Double> enc_time=new ArrayList<>();
				ArrayList<Double> keygen_time=new ArrayList<>();
				byte[] plaintext= "1234567890000000".getBytes();
				XYSeries keygen_series=new XYSeries("Key Generation");
				XYSeries enc_series=new XYSeries("Encryption");
				XYSeries dec_series=new XYSeries("Decryption");
				XYSeriesCollection dataset=new XYSeriesCollection();
				
				for (int keysize:keysizes) {
					ArrayList<Double> dec_time_per_key=new ArrayList<>();
					ArrayList<Double> enc_time_per_key=new ArrayList<>();
					ArrayList<Double> keygen_time_per_key=new ArrayList<>();
					for(int count=0;count<10;count++) {
						AsymmetricBlockCipher cipher=new RSAEngine();
						
						long st_keygen=System.nanoTime();
						
						RSAKeyPairGenerator keygen= new RSAKeyPairGenerator();
						keygen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), keysize, 500));
						AsymmetricCipherKeyPair pair= keygen.generateKeyPair();
										
						long et_keygen=System.nanoTime();
						
						cipher.init(true,pair.getPublic());
						byte[] ciphertext = cipher.processBlock(plaintext, 0, plaintext.length);
					
						long et_enc=System.nanoTime();
						
						cipher.init(false,pair.getPrivate());
						byte[] dec_plaintext = cipher.processBlock(ciphertext, 0, ciphertext.length);
						
						long et_dec=System.nanoTime();

						keygen_time_per_key.add(((et_keygen-st_keygen)/1000000000.0));
						enc_time_per_key.add(((et_enc-et_keygen)/1000000000.0));
						dec_time_per_key.add(((et_dec-et_enc)/1000000000.0));
					}
					
//					System.out.println(keygen_time_per_key.stream().mapToDouble(Double::doubleValue).sum()/keygen_time_per_key.size());
//					System.out.println(enc_time_per_key.stream().mapToDouble(Double::doubleValue).sum()/enc_time_per_key.size());
//					System.out.println(dec_time_per_key.stream().mapToDouble(Double::doubleValue).sum()/dec_time_per_key.size());
//					System.out.println(keygen_time_per_key.size());
					
//					keygen_time.add(keygen_time_per_key.stream().mapToDouble(Double::doubleValue).sum()/keygen_time_per_key.size());
//					enc_time.add(enc_time_per_key.stream().mapToDouble(Double::doubleValue).sum()/enc_time_per_key.size());
//					dec_time.add(dec_time_per_key.stream().mapToDouble(Double::doubleValue).sum()/dec_time_per_key.size());
					if(keysize>500) {
						keygen_series.add(keysize,keygen_time_per_key.stream().mapToDouble(Double::doubleValue).sum()/keygen_time_per_key.size());
						enc_series.add(keysize,enc_time_per_key.stream().mapToDouble(Double::doubleValue).sum()/enc_time_per_key.size());
						dec_series.add(keysize,dec_time_per_key.stream().mapToDouble(Double::doubleValue).sum()/dec_time_per_key.size());
					}
					
//					System.out.println(keygen_time);
//					System.out.println(enc_time);
//					System.out.println(dec_time);
					
				}
				dataset.addSeries(keygen_series);
				dataset.addSeries(enc_series);
				dataset.addSeries(dec_series);
				return dataset;
			}

}
