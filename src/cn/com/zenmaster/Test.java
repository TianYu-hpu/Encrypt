package cn.com.zenmaster;

import cn.com.zenmaster.digest.DigestAlgorithm;
import cn.com.zenmaster.digest.DigestUtil;

/**
 * Created by TianYu on 2016/5/29.
 */
public class Test {

    public static void main(String args[]) {
        String data = "jikexueyuan";

        //DES 加解密
       /* byte[] dessecretKey = DesUtil.getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(dessecretKey));
        byte[] encryptData = DesUtil.encryptData(dessecretKey, data.getBytes());
        System.out.println("des 加密" + BytesToHex.fromBytesToHex(encryptData));
        System.out.println("des 解密" + new String(DesUtil.descryptData(dessecretKey, encryptData)));*/

        // 3DES 加解密
       /* byte[] desedeSecretKey = DesedeUtil.getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(desedeSecretKey));
        byte[] encryptDataDesede = DesedeUtil.encryptData(desedeSecretKey, data.getBytes());
        System.out.println("3des 加密" + BytesToHex.fromBytesToHex(encryptDataDesede));
        System.out.println("3des 解密" + new String(DesedeUtil.descryptData(desedeSecretKey, encryptDataDesede)));*/

        // AES 加解密
        /*byte[] aesSecretKey = AesUtil.getInstance().getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(aesSecretKey));
        byte[] encryptDataAes = AesUtil.getInstance().encryptData(aesSecretKey, data.getBytes());
        System.out.println("aes 加密" + BytesToHex.fromBytesToHex(encryptDataAes));
        System.out.println("aes 解密" + new String(AesUtil.getInstance().descryptData(aesSecretKey, encryptDataAes)));*/

        //摘要算法
        /*System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getMD5Digest(data.getBytes())));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getSHA1Digest(data.getBytes())));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getSHA256Digest(data.getBytes())));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getSHA384Digest(data.getBytes())));
        System.out.println(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getSHA512Digest(data.getBytes())));*/

        //HmacMD5 摘要

        byte[] hmacMD5SecretKey = DigestUtil.getInstance().getHMACSecretKey(DigestAlgorithm.HmacSHA256.getValue());

        System.out.println(BytesToHex.fromBytesToHex(hmacMD5SecretKey));

        System.out.print(BytesToHex.fromBytesToHex(DigestUtil.getInstance().getHMACDigest(hmacMD5SecretKey, data.getBytes(), DigestAlgorithm.HmacSHA256.getValue())));



    }

}
