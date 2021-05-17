
/**
 * @description:
 * @author: Liduoan
 * @time: 2021/4/23
 */

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;


/**
 * @ProjectName: InformationSecurity
 * @Package: PACKAGE_NAME
 * @ClassName: RSA
 * @Author: Administrator
 * @Description: ${description}
 * @Date: 2019/4/19 21:13
 * @Version: 1.0
 */
public class RSA {

    //公钥 n
    private BigInteger publicKeyN;
    //私钥 d
    private BigInteger privateKeyD;
    //大素数 p
    private BigInteger p;
    //大素数 q
    private BigInteger q;
    //Fn = (p-1) * (q-1)
    private BigInteger Fn;

    private int messagelength;
    private int bytes;

    private final BigInteger one = new BigInteger("1");
    private final BigInteger two = new BigInteger("2");

    private HashMap<String,String> map = new HashMap<>();

    public RSA(){

    }

    /**
     * 功能描述:
     * @Param:
     * @param str
     * @param publicKeyN
     * @return: java.lang.String
     */

    public String encode_new(String str,BigInteger publicKeyE,BigInteger publicKeyN) throws UnsupportedEncodingException {
//        BigInteger publicKeyE = getPublicKeyE();

        List<BigInteger> list = encodeMessage(getDealBytes(publicKeyN), str, publicKeyE, publicKeyN);
        //把密文进行拼接，拼接用空格进行隔开
        String encodeMessage = "";
        for (BigInteger m : list) {
            encodeMessage += m.toString() + " ";
        }
//        System.out.println("密文：\n" + encodeMessage);
        //用 Base64 进行编码
        byte[] encodeBase64 = Base64.getEncoder().encode(encodeMessage.getBytes());
        String encodeBase64Str = new String(encodeBase64);

        return encodeBase64Str;
    }

    public String decode_new(String encodeBase64Str,BigInteger privateKeyD,BigInteger publicKeyN) throws UnsupportedEncodingException {
        if(map.containsKey(encodeBase64Str)){
            return map.get(encodeBase64Str);
        }else {

            this.bytes = getDealBytes(publicKeyN);
            byte[] decodeBase64Byte = Base64.getDecoder().decode(encodeBase64Str);
            String decodeBase64Str = new String(decodeBase64Byte);

            //将解码后的密文以空格分隔开
            String[] decodeSplit = decodeBase64Str.split(" ");

            //将分隔开的密文加入到 List 容器中
            List decodeBase64List = new ArrayList();
            for (String b : decodeSplit) {
                decodeBase64List.add((new BigInteger(b)));
            }

            //将密文进行解密
            String decodeMessage = decodeMessage(decodeBase64List, privateKeyD, publicKeyN);

            map.put(encodeBase64Str,decodeMessage);
            return decodeMessage;
        }
    }


    /**
     * 因为 0<M<n,所以可以多个字符处理成一个数，然后把该数进行加密
     * 这样能大大提高加密效率
     * @param publicKeyN
     * @return
     */
    public int getDealBytes(BigInteger publicKeyN) {
        int bytes;
        // 将公钥 N 右移 21 位，当右移后的结果大于 0 时，表示可以一次处理 3 个字符
        // 3 个字符 24 位，每个字符有 1 位为符号位，除符号位剩余 21 位
        if(publicKeyN.shiftRight(21).compareTo(new BigInteger("0")) == 1){
            bytes = 3;
        }else{
            // 右移 14 位
            if (publicKeyN.shiftRight(14).compareTo(new BigInteger("0")) == 1){
                bytes = 2;
            }else{
                bytes = 1;
            }
        }

        return bytes;
    }

    /**
     * 获取公钥 n
     * @return 返回公钥 n
     */
    public BigInteger getPublicKeyN() {
        //从素数表中随机获取两个素数 p、q
        p = PrimeUtil.getRandomPrime();
        q = PrimeUtil.getRandomPrime();
        // n = p * q
        publicKeyN = p.multiply(q);
        // Fn = (p-1) * (q-1)
        Fn = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        return publicKeyN;
    }

    /**
     * 获取公钥 e
     * @return 返回公钥 e
     */
    public BigInteger getPublicKeyE(){
        BigInteger e = two;
        while (true){
            /**
             * e.gcd(Fn)：
             *      说明：获取 e, Fn 的最大公约数（该方法是 BigInteger 内的一个成员方法）
             *      return：返回 e, Fn 的最大公约数（类型为 BigInteger）
             *
             * a.compareTo(b)：
             *      说明：比较 a，b 的大小
             *      return：当 a < b 时，返回 -1；当 a = b 时，返回 0；当 a > b 时，返回 1
             *
             * e.gcd(Fn).compareTo(new BigInteger("1")) == 0
             *      说明：判断 e.gcd(Fn) == 1
             * e.compareTo(Fn) == -1
             *      说明：判断 e < Fn
             */
            if (e.gcd(Fn).compareTo(one) == 0 && e.compareTo(Fn) == -1) {
                break;
            }
            // e++
            e = e.add(one);

        }

        return e;
    }

    /**
     * 获取私钥 d
     * @return 返回私钥 d
     */
    public BigInteger getPrivateKeyD() {
        //获取 d 的值，d 的值的范围为 2 - Fn
        // d = 2
        privateKeyD = two;
        while (true){
            BigInteger e = this.getPublicKeyE();
            /**
             * d.multiply(e).mod(Fn).compareTo(one)
             *      说明：判断 d*e % Fn 是否等于 1，当等于 1 时，返回 0
             * privateKeyD.compareTo(Fn)
             *      说明：比较 d 和 Fn 的大小，当 d < Fn 时，返回 -1；
             */
            if (privateKeyD.multiply(e).mod(Fn).compareTo(one) == 0 && privateKeyD.compareTo(Fn) == -1) {
                break;
            }
            // d++
            privateKeyD = privateKeyD.add(one);

        }
        return privateKeyD;
    }


    /**
     * 根据公钥 e、n，对明文进行加密
     * @param plainText 明文
     * @param publicKeyE 公钥 e
     * @param publicKeyN 公钥 n
     * @return 返回密文
     */
    public String encode(BigInteger plainText, BigInteger publicKeyE, BigInteger publicKeyN){
        // C = M的e次方 % n
        BigInteger C = null;
        //temp = 1
        BigInteger temp = one;

        //while(e > 0)
        while (publicKeyE.compareTo(new BigInteger("0")) == 1){
            //temp = plainText * temp % n;
            temp = plainText.multiply(temp).mod(publicKeyN);
            //e--
            publicKeyE = publicKeyE.subtract(one);
        }
        C = temp;
        return C.toString();
    }

    /**
     * 对字符串进行加密
     * @param bytes ：一次加密字符的个数
     * @param code ：需要加密的明文
     * @param publicKeyE ：公钥 e
     * @param publicKeyN ：公钥 n
     * @return ：返回加密后的字符串，即密文
     * @throws UnsupportedEncodingException
     */
    public List<BigInteger> encodeMessage(int bytes, String code, BigInteger publicKeyE, BigInteger publicKeyN) throws UnsupportedEncodingException{
        this.bytes = bytes;
        //先对字符串进行编码,防止有中文
        byte[] codeBase64 = Base64.getEncoder().encode(code.getBytes());
        code = new String(codeBase64);

        this.messagelength = code.length();
        //将字符串转换为字符数组
        char[] message = code.toCharArray();
        //用于存放密文
        List<BigInteger> result = new ArrayList<>();

        int x, i, j;

        /**
         * i += bytes : 一次对 bytes 个字符进行加密
         * 当字符的个数不足 bytes 时，则一次处理剩余的字符
         * 如：bytes = 3；message.length = 13 时
         *    前4次处理一次性加密3个字符，最后一次加密剩余的
         *    一个字符
         */
        for(i = 0; i < message.length; i+=bytes) {
            x = 0;
            /**
             * 作用：将 bytes 个字符转换为数字
             * j < bytes ：字符剩余大于等于 bytes时，一次处理 bytes 个字符
             * (i+j) < message.length : 表示剩余字符小于 bytes，一次处理 message.length - (i+j)个字符
             */
            for (j = 0; j < bytes && (i+j) < message.length; j++){
                /**
                 *
                 * 对每个字符进行左移位运算
                 * message[i + j] *(1 << (7 * j))：
                 *         说明：一个字符共 8 位，有 1 位为符号位不用移动；所以每个字符左移 7 位
                 *              移位后转换为数字，然后对数字进行加密操作
                 *              1 << (7 * j) --> 表示 2^(7*j)
                 *
                 *         如：同时对 AB 进行加密(AB的 ASCII码分别为 65、66)
                 *         当对 A 处理时，j = 0，x += 65
                 *         当对 B 处理时，j = 1，x += 66 * (1 << (7 * 1)) = 66 * 2^7 = 8513
                 *         此时 x 的二进制为 0010 0001 0100 0001
                 *         后八位 0100 0001 = 65 --> A
                 *               0010 0001 0000 0000 = 8448 --> 66 * 2^7 --> B * (1 << (7 * 1))
                 *
                 */
                x += message[i + j] * (1 << (7 * j));

            }

            BigInteger M = new BigInteger(x+"");
            // 对转换出来的数字进行加密
            String encode = encode(M, publicKeyE, publicKeyN);
            // 将加密的结果存放到 result 容器中
            result.add(new BigInteger(encode));
        }
        return result;
    }

    /**
     * 利用私钥 d 和 公钥 n 对密文 C 进行解密
     * 公式：M = c ^ d % n
     * @param C 密文
     * @param privateKeyD 私钥 d
     * @param publicKeyN 公钥 n
     * @return 返回解密后的明文
     */
    public String decode(BigInteger C, BigInteger privateKeyD, BigInteger publicKeyN){
        BigInteger temp = one;
        // temp = c^d%n
        while (privateKeyD.compareTo(new BigInteger("0")) == 1){
            // temp = c*temp%n
            temp = C.multiply(temp).mod(publicKeyN);
            // d--
            privateKeyD = privateKeyD.subtract(one);
        }

        return  temp.toString();
    }

    /**
     * 对加密的字符进行解密
     * @param encode
     * @param privateKeyD
     * @param publicKeyN
     * @return
     * @throws UnsupportedEncodingException
     */
    public String decodeMessage(List<BigInteger> encode, BigInteger privateKeyD, BigInteger publicKeyN) throws UnsupportedEncodingException{

        String decode = "";
        String x;
        for (int i = 0; i < encode.size(); i++) {
            // 根据私钥 D，公钥 N，对密文进行解密
            x = this.decode(encode.get(i), privateKeyD, publicKeyN);

            /**
             * 由于加密时的字符串的长度不一定是 bytes 的整数倍
             * 所以当处理到最后一个密文时，需要计算加密时，最后一次的加密
             * 加密了几个字符，然后最后解密就一次解密出几个字符
             *
             * 如：bytes = 3, 明文 length = 5
             * 第一次能一次性处理前三个字符，最后剩余的两个字符也一次处理
             * 得到的第一个密文是由前三个字符处理加密得到的，第二个密文是
             * 由最后两个字符处理加密得到的。
             * 所以解密时解密第二个密文，只需处理两次，然后解密得到两个明文
             */
            int count = this.getDealBytes(publicKeyN);
            // 当处理最后一个密文时
            if (i == encode.size()-1){
                // 判断最后一个密文加密时被一次处理了几个字符个数是否是bytes的整数倍
                if (messagelength % bytes != 0){
                    count = messagelength % bytes;
                }
            }

            /**
             * 对同时处理加密的字符进行移位解密，一次解密出 count 个字符
             */
            for (int j = 0; j < count; j++) {
                BigInteger temp = new BigInteger(x);

                /**
                 * 假设对 x 是 AB 两个字符的移位处理的结果（看加密过程）
                 * 即 x = 8513
                 * x 的二进制为 0010 0001 0100 0001
                 * j = 0 --> 8513 % 128 = 65 --> A
                 * j = 1 --> 0010 0001 0100 0001>>7 --> 0000 0000 0100 0010 = 66 --> B
                 */
                BigInteger mod = temp.shiftRight(7 * j).mod(new BigInteger("128"));
                decode += (char) Integer.parseInt(mod.toString());
            }
        }

        //对解密出来的字符串进行中文解码
        byte[] bytes = Base64.getMimeDecoder().decode(decode);
        decode = new String(bytes);
        return decode;
    }





}