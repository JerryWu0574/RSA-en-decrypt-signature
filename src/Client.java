
import javax.swing.*;
import java.awt.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
/**
 * @author JerryWu
 * @date 2021-05-02
 * @desc  Alice端
 */
public  class Client
{

    public static RSA rsa = new RSA();
    // 获取公钥 N
    public static BigInteger publicKeyN = BigInteger.valueOf(4970201);//rsa.getPublicKeyN();
    // 获取私钥 N
    public static BigInteger privateKeyD = BigInteger.valueOf(993101);//rsa.getPrivateKeyD();
    // 获取公钥 E
    public static BigInteger publicKeyE = BigInteger.valueOf(5);//rsa.getPublicKeyE();

    public static void main(String[] args) {

        JFrame frame = new JFrame("Alice");
        frame.setSize(400,600);
        frame.setDefaultCloseOperation(3);
        frame.setLocationRelativeTo(null);
        frame.setResizable(false);

        FlowLayout flow = new FlowLayout();
        frame.setLayout(flow);

        JTextArea ja = new JTextArea();
        Dimension dms = new Dimension(300,200);
        ja.setPreferredSize(dms);
        frame.add(ja);

        JTextField text = new JTextField();
        Dimension dm = new Dimension(300,30);
        text.setPreferredSize(dm);
        frame.add(text);


        JButton send = new JButton("发送");
        frame.add(send);
        frame.setVisible(true);

        JTextArea pass = new JTextArea();
        Dimension ps = new Dimension(300,100);
        pass.setPreferredSize(ps);
        frame.add(pass);

        JTextArea signout = new JTextArea();
        Dimension st = new Dimension(300,100);
        signout.setPreferredSize(st);
        frame.add(signout);



        send.addActionListener(v ->
        {
            try
            {
                String host = "127.0.0.1";
                int port = 12345;
                //创建流套接字并将其连接到指定IP地址的指定端口号。
                Socket socket = new Socket(host, port);
                //返回此套接字的输出流
                DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());


                String submitText = text.getText();
                ja.append("Alice："+submitText+"\n");
                //加密应该用服务端的公钥
                String str = Server.rsa.encode_new(submitText,Server.publicKeyE,Server.publicKeyN);


                // Log
                System.out.println("========Alice========");
                System.out.println("原文："+submitText);
                System.out.println("密文："+str);
                System.out.println("=====================");
                //发送框清空
                text.setText("");

                outputStream.writeUTF(str);

                //签名
                /**
                 1. A计算消息m的消息摘要,记为 h(m)
                 2. A使用私钥(n,d)对h(m)加密,生成签名s, s满足:s=(h(m))^d mod n;
                 由于A是用自己的私钥对消息摘要加密,所以只用使用s的公钥才能解密该消息摘要,这样A就不可否认自己发送了该消息给B
                 3. A发送消息和签名(m,s)给B
                 **/
                String sign = HashUtil.messageDigestAlgorithm(submitText);
//                System.out.println(sign);
                outputStream.writeUTF(sign);

                DataInputStream inputStream = new DataInputStream(socket.getInputStream());


                outputStream.close();
                inputStream.close();
                socket.close();
                //空行Log
                System.out.println("");
            }
            catch (IOException e)
            {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });


        ServerSocket serverSocket = null;
        try
        {
            serverSocket = new ServerSocket(12346);
            while (true)
            {
                Socket socket = serverSocket.accept();
                DataInputStream inputStream = new DataInputStream(socket.getInputStream());
                //解密
                String str = inputStream.readUTF();
                String res = Client.rsa.decode_new(str, Client.privateKeyD, Client.publicKeyN);
                ja.append("Bob："+res+"\n");
                pass.append("收到密文："+str+"\n");


                //Log
                System.out.println("========收到Bob端========");
                System.out.println("收到密文："+str);
                System.out.println("原文："+res);


                //解签
                /**
                 * 1. B计算消息m的消息摘要(计算方式和A相同),记为h(m)
                 2. B使用A的公  钥(n,e)解密s,得到 H(m), H(m) = s^e mod n
                 3. B比较H(m)与h(m),相同才能证明验签成功
                 */

                String signOrgin = HashUtil.messageDigestAlgorithm(res);
                String signNow = inputStream.readUTF();

                System.out.println("==========签名验证==========");

                if(signNow.equals(signOrgin)){
                    System.out.println("========验证成功========");
                }else{
                    System.out.println("========验证失败========");
                }
                System.out.println("======================");
                signout.append("签名："+signNow+"\n");


                DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
                inputStream.close();
                outputStream.close();
                socket.close();
                //空行Log
                System.out.println("");
            }
        }
        catch (IOException e)
        {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally
        {
            try
            {
                serverSocket.close();
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
        }

    }
}