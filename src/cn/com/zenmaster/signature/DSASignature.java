package cn.com.zenmaster.signature;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import cn.com.zenmaster.KeyUtil;
import cn.com.zenmaster.asymmetric.AsymmetricAlgorithm;

/**
 * Created by tianyu on 16-6-2.
 */
public class DSASignature extends KeyUtil {

	private static DSASignature instance;

	public static DSASignature getInstance() {
		if(instance == null) {
			instance = new DSASignature();
		}
		return instance;
	}

	/**
	 *  生成签名
	 *
	 * @param data
	 * @return
	 */
	public byte[] sign(byte[] privateKey, byte[] data) {
		byte[] sign = null;
		try {
			//实例化Signature
			Signature signature = Signature.getInstance(SignatureAlgorithm.SHAwithDSA);
			//初始化Signature
			signature.initSign(getPrivateKey(privateKey));
			//更新数据
			signature.update(data);
			//签名
			sign = signature.sign();
		} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return sign;
	}

	/** 验证签名
	 *
	 * @param sign
	 * @param data
	 * @param publicKey
	 * @return
	 */
	public boolean verify(byte[] sign, byte[] data, byte[] publicKey) {
		boolean result = false;
		try {
			//实例化Signature
			Signature signature = Signature.getInstance(SignatureAlgorithm.SHAwithDSA);
			//初始化Signature
			signature.initVerify(getPublicKey(publicKey));
			//更新数据
			signature.update(data);
			//验证
			result = signature.verify(sign);
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			e.printStackTrace();
		}
		return result;
	}


	@SuppressWarnings("Duplicates")
	@Override
	public PublicKey getPublicKey(byte[] publicKey) {
		PublicKey pubKey = null;
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(AsymmetricAlgorithm.DSA);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
			pubKey = keyFactory.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return pubKey;
	}

	@SuppressWarnings("Duplicates")
	@Override
	public PrivateKey getPrivateKey(byte[] privateKey) {
		PrivateKey priKey = null;
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(AsymmetricAlgorithm.DSA);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
			priKey = keyFactory.generatePrivate(keySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return priKey;
	}
}
