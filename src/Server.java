

import javax.swing.*;
import java.awt.*;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * @description:
 * @author: Liduoan
 * @time: 2021/4/21
 */
public class Server {

    public static RSA rsa = new RSA();
    // 获取公钥 N
    public static BigInteger publicKeyN = BigInteger.valueOf(20647381);//rsa.getPublicKeyN();
    // 获取私钥 N
    public static BigInteger privateKeyD = BigInteger.valueOf(3);//rsa.getPrivateKeyD();
    // 获取公钥 E
    public static BigInteger publicKeyE = BigInteger.valueOf(13758835);//rsa.getPublicKeyE();

    public static void main(String[] args)
    {
        JFrame frame = new JFrame("Bob");
        frame.setSize(400, 600);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);


        FlowLayout flow = new FlowLayout();
        frame.setLayout(flow);

        JTextArea text = new JTextArea();
        Dimension dms = new Dimension(300,200);
        text.setPreferredSize(dms);
        frame.add(text);


        JTextField context = new JTextField();
        Dimension dm = new Dimension(300,30);
        context.setPreferredSize(dm);
        frame.add(context);

        JButton send = new JButton("发送");
        frame.add(send);

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
                int port = 12346;
                Socket socket = new Socket(host, port);
                DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());

                String submitText = context.getText();
                //这里需要同步把信息在消息框显示--
                text.append("Bob："+submitText+"\n");
                String str = Client.rsa.encode_new(submitText, Client.publicKeyE, Client.publicKeyN);
                //把我们输入的信息发送过去
                outputStream.writeUTF(str);

                //Log
                System.out.println("========Bob========");
                System.out.println("原文："+submitText);
                System.out.println("密文："+str);
                System.out.println("=====================");

                //清空输入框
                context.setText("");

                //签名
                /**
                 1. A计算消息m的消息摘要,记为 h(m)
                 2. A使用私钥(n,d)对h(m)加密,生成签名s, s满足:s=(h(m))^d mod n;
                 由于A是用自己的私钥对消息摘要加密,所以只用使用s的公钥才能解密该消息摘要,这样A就不可否认自己发送了该消息给B
                 3. A发送消息和签名(m,s)给B
                 **/
                String sign = HashUtil.messageDigestAlgorithm(submitText);
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
            serverSocket = new ServerSocket(12345);
            while (true)
            {
                Socket socket = serverSocket.accept();
                DataInputStream inputStream = new DataInputStream(socket.getInputStream());

                String str = inputStream.readUTF();
                String res = Server.rsa.decode_new(str, Server.privateKeyD, Server.publicKeyN);
                text.append("Alice："+res+"\n");
                pass.append("收到密文："+str+"\n");

                //Log
                System.out.println("========收到Alice=======");
                System.out.println("收到密文："+str);
                System.out.println("原文："+res);
//                System.out.println("=====================");

                //解签
                /**
                 * 1. B计算消息m的消息摘要(计算方式和A相同),记为h(m)
                 2. B使用A的公钥(n,e)解密s,得到 H(m), H(m) = s^e mod n
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
