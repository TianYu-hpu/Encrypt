package cn.com.zenmaster;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by tianyu on 16-6-2.
 * 生成不同形式的公钥和私钥
 */
public abstract class KeyUtil {

	public static final String PUBLIC_KEY = "PULIC_KEY";
	public static final String PRIVATE_KEY = "PRIVATE_KEY";

	/** 通过PublicKey获取字节数组的publicKey
	 *
	 * @param publicKey
	 * @return
	 */
	public static byte[] getPublicKey(PublicKey publicKey) {
		return publicKey.getEncoded();
	}

	public static byte[] getPrivateKey(PrivateKey privateKey) {
		return privateKey.getEncoded();
	}

	/**
	 *  产生PublicKey形式的公钥
	 *
	 * @param publicKey
	 * @return
	 */
	public abstract PublicKey getPublicKey(byte[] publicKey);


	/**
	 *  产生PrivateKey形式的私钥
	 *
	 * @param privateKey
	 * @return
	 */
	public abstract PrivateKey getPrivateKey(byte[] privateKey);

}
