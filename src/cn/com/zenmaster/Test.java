package cn.com.zenmaster;

/**
 * Created by TianYu on 2016/5/29.
 */
public class Test {

    public static void main(String args[]) {

        String data = "hello";
        //DES 加解密
        byte[] secretKey = DesUtil.getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(secretKey));
        byte[] encryptData = DesUtil.encryptData(secretKey, data.getBytes());
        System.out.println("des 加密" + BytesToHex.fromBytesToHex(encryptData));
        System.out.println("des 解密" + new String(DesUtil.descryptData(secretKey, encryptData)));

        // 3DES 加解密
        byte[] desedeSecretKey = DesedeUtil.getSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(desedeSecretKey));
        byte[] encryptDataDesede = DesedeUtil.encryptData(desedeSecretKey, data.getBytes());
        System.out.println("3des 加密" + BytesToHex.fromBytesToHex(encryptDataDesede));
        System.out.println("3des 解密" + new String(DesedeUtil.descryptData(desedeSecretKey, encryptDataDesede)));
    }

}
