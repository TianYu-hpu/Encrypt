package cn.com.zenmaster;

/**
 * Created by TianYu on 2016/5/29.
 * 将byte数组转换为16进制字符串
 */
public class BytesToHex {

    /**
     *  将byte数组转换为字符串
     *
     * @param bytes
     * @return
     */
    public static String fromBytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for(int i = 0;i < bytes.length;i++) {
            if(Integer.toHexString(0xFF & bytes[i]).length() == 1) {
                sb.append("0").append(Integer.toHexString(0xFF & bytes[i]));
            } else {
                sb.append(Integer.toHexString(0xFF & bytes[i]));
            }
        }
        return sb.toString();
    }
}
