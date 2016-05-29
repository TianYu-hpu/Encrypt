package cn.com.zenmaster;

/**
 * Created by TianYu on 2016/5/29.
 */
public class Test {

    public static void main(String args[]) {

        String data = "hello";
        byte[] secretKey = DesUtil.getDesSecretKey();
        System.out.println("secretKey" + BytesToHex.fromBytesToHex(secretKey));
        byte[] encryptData = DesUtil.encryptData(secretKey, data.getBytes());
        System.out.println("des 加密" + BytesToHex.fromBytesToHex(encryptData));
        System.out.println("des 解密" + new String(DesUtil.descryptData(secretKey, encryptData)));
    }

}
