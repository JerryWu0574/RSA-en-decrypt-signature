
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;



public class Rsa_Test {

    public static void main(String[] args) throws UnsupportedEncodingException {
        RSA rsa = new RSA();
        // 获取公钥 N
        BigInteger publicKeyN = rsa.getPublicKeyN();

        // 获取公钥 E
        BigInteger publicKeyE = rsa.getPublicKeyE();
        // 获取私钥 D
        BigInteger privateKeyD = rsa.getPrivateKeyD();


        System.out.println("公钥 publicKeyN = " + publicKeyN);
        System.out.println("公钥 publicKeyE = " + publicKeyE);
        System.out.println("私钥 privateKeyD = " + privateKeyD);

        String content = "netsecurityweek";

        //加密 需要 公钥 N
        String encodeBase64Str = rsa.encode_new(content,publicKeyE, publicKeyN);
        System.out.println(encodeBase64Str);
        //将密文进行解码 需要私钥 D 公钥 N
        String decodeMessage = rsa.decode_new(encodeBase64Str, privateKeyD, publicKeyN);
        //String decodeMessage = rsa.decode_new("MjE0OTg2NCA1MzA2NDU1IDEwMjg5NzQyIDE2MTMzNzEzIDIzNTkzNDMgOTU0MjQ3OSAzNzIzMTUyIA==", BigInteger.valueOf(36630461), BigInteger.valueOf(45802517));

        System.out.println("解密结果：\n" + decodeMessage);
    }
}
