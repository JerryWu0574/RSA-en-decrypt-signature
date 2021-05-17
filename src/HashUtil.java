
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil {

    /**
     * MD5/SHA消息摘要
     * @param content 数据
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String messageDigestAlgorithm(String content) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("md5");
        byte[] result = messageDigest.digest(content.getBytes());
        StringBuilder sb = new StringBuilder();
        for(byte b : result){
            //转16进制
            String a = Integer.toHexString(b & 0xff);
            //长度为1时在最高位补0
            if(a.length() == 1){
                a = "0" + a;
            }
            sb.append(a);
        }
        return sb.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.println(messageDigestAlgorithm("netsecurityweek"));//b7c58f860f1add7de092b1f2931a3eb9
        System.out.println(messageDigestAlgorithm("netsecurityweek"));//ff0e2136bc6df62bbe0d9b6ad9d028852312aad5
    }
}