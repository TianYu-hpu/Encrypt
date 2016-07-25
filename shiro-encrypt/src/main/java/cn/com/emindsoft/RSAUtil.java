package cn.com.emindsoft;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;


public class RSAUtil {
	
	public static final String AsymmetricAlgorithm = "RSA";
	public static final String PUBLIC_KEY = "PULIC_KEY";
	public static final String PRIVATE_KEY = "PRIVATE_KEY";

	
	/**
	 *  初始化公钥和私钥
	 * 
	 * @return
	 */
	public static Map<String, Object> initKey() {
		Map<String, Object> map = null;
        try {
            //创建密钥对生成器  非对称加密算法
            KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance(AsymmetricAlgorithm);
            pairGenerator.initialize(1024);
            //生成密钥对
            KeyPair keyPair = pairGenerator.generateKeyPair();
            //生成公钥和私钥
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            map = new HashMap<String, Object>();
            map.put(PUBLIC_KEY, publicKey);
            map.put(PRIVATE_KEY, privateKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return map;
	}
	
	/** 获取公钥
	 * 
	 * @param keyMap
	 * @return
	 */
	public static RSAPublicKey getPublicKey(Map<String, Object> keyMap){
		RSAPublicKey publicKey = (RSAPublicKey) keyMap.get(PUBLIC_KEY);
		return publicKey;
	}
	
	/** 获取私钥
	 * 
	 * @param keyMap
	 * @return
	 */
	public static RSAPrivateKey getPrivateKey(Map<String, Object> keyMap){
		RSAPrivateKey privateKey = (RSAPrivateKey) keyMap.get(PRIVATE_KEY);
		return privateKey;
	}
    
    /** 加密
    *
    * @param data
    * @return
    */
   public static byte[] encryptData(RSAPublicKey publicKey, byte[] data) throws Exception {
		//2. Cipher 完成加密工作
		Cipher cipher = Cipher.getInstance(AsymmetricAlgorithm);
		// 3. 根据秘钥对cipher进行初始化
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		// 4. 加密
		byte[] cliperBytes = cipher.doFinal(data);
		return cliperBytes;
   }

   /** 解密
    *
    * @param data
    * @return
    */
   public static byte[] descryptData(RSAPrivateKey privateKey, byte[] data) throws Exception {
       //2. Cipher 完成解密工作
       Cipher cipher = Cipher.getInstance(AsymmetricAlgorithm);
       //3. 根据秘钥对cipher进行初始化
       cipher.init(Cipher.DECRYPT_MODE, privateKey);
       //4. 解密
       byte[] plainBytes = cipher.doFinal(data);
       return plainBytes;
   }
	
}
