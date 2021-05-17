
/**
 * @description:
 * @author: Liduoan
 * @time: 2021/4/23
 */
import java.math.BigInteger;
import java.util.Random;

/**
 * @ProjectName: InformationSecurity
 * @Package: PACKAGE_NAME
 * @ClassName: PrimeUtil
 * @Author: Administrator
 * @Description: ${description}
 * @Date: 2019/4/20 0:33
 * @Version: 1.0
 */
public class PrimeUtil {
    //定义素数的开始
    public static int begin = 2;
    //定义素数的结束
    public static int N = 10000;
    //定义素数表2的大小，需要根据实际定
    public static int M = 1230;
    //素数打表法，所用到的素数表
    public static int[] primeTable = new int[N];
    //素数表2，存放一定范围内的所有素数
    public static int[] prime = new int[M];

    static {
        int i;
        //值 为 1表示为素数，值为 0 表示为非素数
        //把表中所有的值都设置为1
        for (i = begin; i <= N-1; i++){
            primeTable[i] = 1;
        }

        for (i = begin; i <= N-1; i++){
            if (primeTable[i] == 0){
                continue;
            }
            for (int j = i+i; j <= N-1; j += i){
                primeTable[j] = 0;
            }
        }

        int j = 1;
        for (i = begin; i <= N - 1; i++){
            if(primeTable[i] == 1) {
                prime[j++] = i;
            }
        }

    }

    public static BigInteger getRandomPrime(){
        //随机从素数表 prime 中取出两个素数p, q，素数表中的素数范围为2-9973
        Random random = new Random();
        return new BigInteger(PrimeUtil.prime[random.nextInt(M-1)] + "");
    }

    public static void main(String[] args) {
        System.out.println("产生一个随机数为："+PrimeUtil.getRandomPrime());
    }

}
