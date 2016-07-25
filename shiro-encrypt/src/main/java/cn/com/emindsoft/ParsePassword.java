package cn.com.emindsoft;

import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.util.ByteSource;

public class ParsePassword {

	/**
	 * 密码明文加密存入数据库
	 * 
	 * @param plainPassword
	 * @return
	 */
	public static String hashPassword(String plainPassword) {
		String salt = generatetPrivateSalt();

		DefaultHashService hashService = new DefaultHashService();
		hashService.setHashAlgorithmName("SHA-512");
		hashService.setPrivateSalt(ByteSource.Util.bytes(salt.getBytes()));
		hashService.setHashIterations(1);
		HashRequest request = new HashRequest.Builder().setAlgorithmName("SHA")
				.setSource(ByteSource.Util.bytes(plainPassword)).setSalt(ByteSource.Util.bytes(salt.getBytes()))
				.setIterations(256).build();
		String hex = hashService.computeHash(request).toHex();
		return hex;
	}

	/**
	 * 生成私盐
	 * 
	 * @return
	 */
	private static String generatetPrivateSalt() {
		SecureRandomNumberGenerator randomNumberGenerator = new SecureRandomNumberGenerator();
		ByteSource privateSalt = randomNumberGenerator.nextBytes();
		String salt = BytesToHex.fromBytesToHex(privateSalt.getBytes());
		System.out.println("私盐:" + salt);
		return salt;
	}

	/**
	 *  用户传入的密码经过加密后和数据库中存储的密码进行比较
	 * 
	 * @param plainPassword
	 * @return
	 */
	public static boolean matchPassword(String plainPassword) {
		//从数据库中获取到该用户的私盐
		String salt = "33ca59835943792ce91fbf01ea2b09ad";
		//数据库中存储的加密后的密码
		String cliperPassword = "52365f8ac1a0ab1b9fd5ee618b697116161c3f95";
		
		System.out.println("私盐:" + salt);
		DefaultHashService hashService = new DefaultHashService();
		hashService.setHashAlgorithmName("SHA-512");
		hashService.setPrivateSalt(ByteSource.Util.bytes(salt.getBytes())); // 私盐，默认无
		hashService.setHashIterations(1);
		HashRequest request = new HashRequest.Builder().setAlgorithmName("SHA")
				.setSource(ByteSource.Util.bytes(plainPassword)).setSalt(ByteSource.Util.bytes(salt.getBytes()))
				.setIterations(256).build();
		String hex = hashService.computeHash(request).toHex();
		System.out.println("result:" + hex);
		if(hex.equals(cliperPassword)) {
			return true;
		} else {
			return false;
		}
		
	}
}
