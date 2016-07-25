package cn.com.emindsoft;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

/**
 * Hello world!
 *
 */
public class App {
	
	public static void main(String[] args) throws Exception {
		/*String password = "123456";
		System.out.println("明文:"  + password);
		
		//初始化公钥和私钥
		Map<String, Object> encryptKey = RSAUtil.initKey();
		RSAPublicKey publicKey = RSAUtil.getPublicKey(encryptKey);
		System.out.println("公钥:" + BytesToHex.fromBytesToHex(publicKey.getEncoded()));
		
		RSAPrivateKey privateKey = RSAUtil.getPrivateKey(encryptKey);
		System.out.println("私钥:" + BytesToHex.fromBytesToHex(privateKey.getEncoded()));
		
		byte[] cliperTextByte = RSAUtil.encryptData(publicKey, password.getBytes());
		String cliperText = BytesToHex.fromBytesToHex(cliperTextByte);
		System.out.println("加密后的密文:" + cliperText);
		
		byte[] decodeTextByte = RSAUtil.descryptData(privateKey, cliperTextByte);
		System.out.println("解密后的明文:" + new String(decodeTextByte));*/
		
		/*String password = "123456";
		String cliperPassword = ParsePassword.hashPassword(password);
		
		System.out.println("加密后的密码:" + cliperPassword);*/
		
		System.out.println("结果:" + ParsePassword.matchPassword("123456"));
		
	}
}
