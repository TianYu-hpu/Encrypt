package cn.com.zenmaster.signature;

/**
 * Created by tianyu on 16-6-2.
 * 签名算法
 */
public class SignatureAlgorithm {

	public static final String MD2withRSA = "MD2withRSA";
	public static final String MD5withRSA = "MD5withRSA";
	public static final String SHAwithRSA = "SHA1withRSA";
	public static final String SHA256withRSA = "SHA256withRSA";
	public static final String SHA384withRSA = "SHA384withRSA";
	public static final String SHA512withRSA = "SHA512withRSA";

	//DSA 算法实现就是 RSA 数字签名算法实现的简装版，仅支持 SHA 系列算法
	public static final String SHAwithDSA = "SHA1withDSA";
	public static final String SHA256withDSA = "SHA256withDSA";
	public static final String SHA384withDSA = "SHA384withDSA";
	public static final String SHA512withDSA = "SHA512withDSA";

}
