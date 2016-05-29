package cn.com.zenmaster;

/**
 * Created by TianYu on 2016/5/29.
 */
public class Test {

    public static void main(String args[]) {

        String data = "hello";
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
        byte[] aesSecretKey = AesUtil.getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(aesSecretKey));
        byte[] encryptDataAes = AesUtil.encryptData(aesSecretKey, data.getBytes());
        System.out.println("aes 加密" + BytesToHex.fromBytesToHex(encryptDataAes));
        System.out.println("aes 解密" + new String(AesUtil.descryptData(aesSecretKey, encryptDataAes)));
    }

}
