package com.example.chattingapp;

import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class ChatController {
    /*
    UI 코드
     */
    @FXML
    private TextArea outputTxt;
    @FXML
    private Button sendBtn;
    @FXML
    private TextArea inputTxt;
    @FXML
    private TextField serverTxt;
    @FXML
    private TextField portTxt;
    @FXML
    private TextField myId;
    @FXML
    private TextField friendId;
    @FXML
    private Button connectBtn;
    @FXML
    private Button loginBtn;
    @FXML
    private Button friendIdBtn;
    @FXML
    private Button exchangeUKeyBtn;
    @FXML
    private Button exchangeKIBtn;
    @FXML
    private Button logoutBtn;
    @FXML
    private Button exchangeNewKIBtn;
    @FXML
    private Button clearOutputTxtBtn;

    @FXML
    protected void onConnectBtnClick() throws IOException {
        //사용자가 입력한 server와 port를 변수에 저장
        try {
            //ui로 구현하려고 하니 서버로부터 받는 메시지를 계속해서 받기위해서는 thread로 받아야 됨
            Thread receiverThread=new Thread(new MessageReceiver(this));
            receiverThread.start();
            outputTxt.appendText("서버에 연결 중입니다.\n");
            connectBtn.setDisable(true);
            initKey();
        } catch (UnknownHostException ex) {
            outputTxt.appendText("\n연결 실패, 호스트 정보를 확인하세요.\n");
            connectBtn.setDisable(false);
        } catch (IOException ex) {
            outputTxt.appendText("\n소켓 통신 중 문제가 발생하였습니다.\n");
            connectBtn.setDisable(false);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    @FXML
    protected void onSendBtnClick() throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        message="3EPROTO MSGSEND\n" +
                "From: "+id+"\n" +
                "To: "+chatterId+"\n" +
                "Nonce: A/Xqf\n" +
                "\n"+inputTxt.getText();
        if(connectBtn.isDisabled()) {
            Thread senderThread = new Thread(new MessageSender(this));
            outputTxt.appendText("==== send ====\n" + inputTxt.getText() + "\n");
            senderThread.start();
            inputTxt.setText("");
        }
        else{
            outputTxt.appendText("\n서버와 연결이 되지 않았습니다.\n");
        }
    }

    @FXML
    protected void OnLoginBtnClick() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        id=myId.getText();
        message="3EPROTO CONNECT\nCredential: "+id;
        if(connectBtn.isDisabled()) {
            Thread senderThread = new Thread(new MessageSender(this));
            senderThread.start();
            inputTxt.setText("");
        }
        else{
            outputTxt.appendText("\n서버와 연결이 되지 않았습니다.\n");
        }
    }

    @FXML
    protected void OnfriendIdBtnClick(){
        chatterId=friendId.getText();
        outputTxt.appendText(chatterId+"님을 수신자로 설정하였습니다.\n");
    }

    @FXML
    protected void OnExchangeUKeyBtnClick() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        message="3EPROTO KEYXCHG\n" +
                "Algo: AES-256-CBC\n" +
                "From: " +id+"\n"+
                "To: "+chatterId+"\n" +
                "\n"+
                publicKey;
        if(connectBtn.isDisabled()) {
            Thread senderThread = new Thread(new MessageSender(this));
            senderThread.start();
            inputTxt.setText("");
        }
        else{
            outputTxt.appendText("\n서버와 연결이 되지 않았습니다.\n");
        }
    }

    @FXML
    protected void OnExchangeKIBtnClick() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        message="3EPROTO KEYXCHG\n" +
                "Algo: AES-256-CBC\n" +
                "From: " + id + "\n" +
                "To: " + chatterId + "\n" +
                "\n" +
                keyAES +
                "\n" +
                iv;
        if(connectBtn.isDisabled()) {
            Thread senderThread = new Thread(new MessageSender(this));
            senderThread.start();
            inputTxt.setText("");
        }
        else{
            outputTxt.appendText("\n서버와 연결이 되지 않았습니다.\n");
        }
    }

    @FXML
    protected void OnExchangeNewKIBtnClick() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException {
        initAESKeyIv();
        message="3EPROTO KEYXCHGRST\n" +
                "Algo: AES-256-CBC\n" +
                "From: "+id+"\n" +
                "To: "+chatterId+"\n" +
                "\n" +
                keyAES+
                "\n" +
                iv;
        if(connectBtn.isDisabled()) {
            Thread senderThread = new Thread(new MessageSender(this));
            senderThread.start();
            inputTxt.setText("");
        }
        else{
            outputTxt.appendText("\n서버와 연결이 되지 않았습니다.\n");
        }
    }

    @FXML
    protected void onClearOutputTxtBtnClick(){
        outputTxt.setText("");
    }

    @FXML
    protected void onLogoutBtnBtnClick() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        message="3EPROTO DISCONNECT\n" +
                "Credential: "+id;
        if(connectBtn.isDisabled()) {
            Thread senderThread = new Thread(new MessageSender(this));
            senderThread.start();
            inputTxt.setText("");
        }
        else{
            outputTxt.appendText("\n서버와 연결이 되지 않았습니다.\n");
        }
    }
    /*
    암호화 코드
    */

    private Socket clientSocket = null;
    private String id;//사용자 신원명

    String message;
    String publicKey;
    String privateKey;
    String chatterPublicKey;
    String chatterId;
    String keyAES;
    String iv;
    SecretKey secretKey;
    IvParameterSpec ivParameterSpec;
    SecureRandom random=new SecureRandom();


    public void initKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        //공개키와 개인키를 초기화
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, secureRandom);
        KeyPair keyPair=keyPairGenerator.genKeyPair();

        PublicKey uKey=keyPair.getPublic();
        PrivateKey rKey=keyPair.getPrivate();

        this.publicKey= Base64.getEncoder().encodeToString(uKey.getEncoded());
        this.privateKey=Base64.getEncoder().encodeToString(rKey.getEncoded());

        initAESKeyIv();
    }

    public void initAESKeyIv() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException {
        //대칭Key 생성
        KeyGenerator generator= KeyGenerator.getInstance("AES");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.init(256, random);
        secretKey=generator.generateKey();
        keyAES = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        //IV 생성
        byte[] ivBytes = new byte[16];

        random.nextBytes(ivBytes);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        ivParameterSpec=ivSpec;
        iv=Base64.getEncoder().encodeToString(((ivSpec.getIV())));
    }

    public String encodeAES(String plainTxt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        byte[] encrypted=cipher.doFinal(plainTxt.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decodeAES(String cipherTxt) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decrypted=Base64.getDecoder().decode(cipherTxt);
        byte[] plainByte=cipher.doFinal(decrypted);

        return new String(plainByte, "UTF-8");
    }

    //매개변수 : 평문, 상대방 publicKey
    //RSA로 encode
    public String encodeRSA(String plainData, String stringPublicKey) {
        String encryptedData = null;
        try {
            //공개키를 공개키객체로 만들기
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] bytePublicKey = Base64.getDecoder().decode(stringPublicKey.getBytes());
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            //암호화
            byte[] byteEncryptedData = cipher.doFinal(plainData.getBytes());
            encryptedData = Base64.getEncoder().encodeToString(byteEncryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedData;
    }

    //매개변수 : 평문, 나의 privateKey
    //RSA로 decode
    public String decodeRSA(String encryptedData, String stringPrivateKey) {
        String decryptedData = null;
        try {
            //평문으로 전달받은 개인키를 개인키객체로 만드는 과정
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] bytePrivateKey = Base64.getDecoder().decode(stringPrivateKey.getBytes());
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            //만들어진 개인키객체를 기반으로 암호화모드로 설정하는 과정
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            //암호문을 평문화하는 과정
            byte[] byteEncryptedData = Base64.getDecoder().decode(encryptedData.getBytes());
            byte[] byteDecryptedData = cipher.doFinal(byteEncryptedData);
            decryptedData = new String(byteDecryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedData;
    }

    public String getId()
    {
        return id;
    }

    public String getFriendId(){
        return chatterId;
    }

    //보낼 때 암호화해서 보내는 함수
    public String getMessage() throws InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String m=message;
        String newM=m;
        message="";

            String[] arr = m.split("\n");

            if (arr[0].equals("3EPROTO KEYXCHG") || arr[0].equals("3EPROTO KEYXCHGRST")) { //키 교환하는 것이면
                //대칭키와 IV교환하는 거면 상대방 공개키로 암호화해서 보내야함
                if (arr.length == 7) {
                    newM = "";
                    System.out.println("암호화 전 key : " + arr[5]);
                    System.out.println("암호화 전 iv : " + arr[6]);
                    arr[5] = encodeRSA(arr[5], chatterPublicKey);
                    arr[6] = encodeRSA(arr[6], chatterPublicKey);
                    System.out.println("암호화 후 key : " + arr[5]);
                    System.out.println("암호화 후 iv : " + arr[6]);

                    newM = makeNewMessage(arr);
                }
            } else if (arr[0].equals("3EPROTO MSGSEND")) {
                for (int i = 5; i < arr.length; i++) {
                    System.out.println("평문 : " + arr[i]);
                    arr[i] = encodeAES(arr[i]);
                    System.out.println("암호문 : " + arr[i]);
                }

                newM = makeNewMessage(arr);
            }

        return newM;
    }
    public String getServer(){
        return serverTxt.getText();
    }
    public int getPort(){
        return Integer.parseInt(portTxt.getText());
    }
    public void txtFromServer(String str){
        outputTxt.appendText(str);
    }

    public Socket getSocketContext() {
        return clientSocket;
    }
    public void setSocketContext(Socket _clientSocket){
        this.clientSocket=_clientSocket;
    }

    public void setChatterPublickKey(String _publickKey){
        chatterPublicKey=_publickKey;
    }

    //복호화하여 Key와 IV를 저장해야됨
    public void setKeyIv(String m, String _keyAES, String _iv)
    {
        System.out.println("복호화 전 key : "+_keyAES);
        System.out.println("복호화 전 iv : "+_iv);
        this.keyAES=decodeRSA(_keyAES, privateKey);
        this.iv=decodeRSA(_iv, privateKey);

        secretKey=new SecretKeySpec(Base64.getDecoder().decode(keyAES), "AES");
        ivParameterSpec=new IvParameterSpec(Base64.getDecoder().decode(iv));

        String[] arr=m.split("\n");
        arr[6]=keyAES;
        arr[7]=iv;

        System.out.println("복호화 후 key : "+keyAES);
        System.out.println("복호화 후 iv : "+iv);
    }

    //받은 메시지 복호화
    public String recvDecodeM(String m) throws InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String[] arr=m.split("\n");
        String newM="";
        for(int i=5; i<arr.length;i++){
            System.out.println("암호문 : "+arr[i]);
            arr[i]=decodeAES(arr[i]);
            System.out.println("평문 : "+arr[i]);
            newM+=arr[i]+"\n";
        }

        return newM;
    }

    public String makeNewMessage(String[] arr){
        String newM="";
        for(int i=0; i<arr.length;i++){
            if(i==(arr.length-1)){
                break;
            }
            newM+=arr[i]+"\n";
        }
        newM+=arr[arr.length-1];

        return newM;
    }

    public void setConnectBtnAble(){
        connectBtn.setDisable(false);
    }
}

// 사용자 입력을 통한 메세지 전송을 위한 Sender Runnable Class
// 여기에서 메세지 전송 처리를 수행합니다.
class MessageSender implements Runnable {
    ChatController clientContext;
    OutputStream socketOutputStream;
    String message;
    Socket clientSocket;

    public MessageSender(ChatController context) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        clientContext = context;
        message= clientContext.getMessage();
        clientSocket = clientContext.getSocketContext();
        socketOutputStream = clientSocket.getOutputStream();
    }

    @Override
    public void run() {
        Scanner scanner = new Scanner(System.in);
        try {
            byte[] payload = message.getBytes(StandardCharsets.UTF_8);
            socketOutputStream.write(payload, 0, payload.length);
        } catch (IOException ex) {

        }
    }
}

// 서버로부터 오는 메시지를 받기 위한 Receiver Runnable Class
class MessageReceiver implements Runnable {
    ChatController clientContext;
    private Socket clientSocket = null;
    private String hostname;
    private int port;
    public MessageReceiver(ChatController context) throws IOException{
        clientContext=context;
        hostname=context.getServer();
        port=context.getPort();
    }

    @Override
    public void run() {
        clientSocket = new Socket();
        try {
            clientSocket.connect(new InetSocketAddress(hostname, port));
            clientContext.setSocketContext(clientSocket);
            clientContext.txtFromServer("서버에 연결되었습니다!\n로그인 해주세요!\n");
        } catch (IOException e) {
            clientContext.txtFromServer("잘못된 hostname 또는 port 입니다.");
            clientContext.setConnectBtnAble();
        }

        InputStream stream = null;
        try {
            stream = clientSocket.getInputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }

        while (true) {
            try {
                if (clientSocket.isClosed()) {
                    break;
                }

                byte[] recvBytes = new byte[2048];
                int recvSize = stream.read(recvBytes);

                if (recvSize == 0) {
                    continue;
                }

                String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);

                parseReceiveData(recv);
            } catch (IOException ex) {
                clientContext.txtFromServer("\n소켓 데이터 수신 중 문제가 발생하였습니다.");
                clientContext.setConnectBtnAble();
                break;
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        }

        try {
            if (clientSocket.isConnected()) {
                clientSocket.close();
            }
        } catch ( IOException ex) {
            clientContext.txtFromServer("\n종료되었습니다.");
        }
    }

    public void parseReceiveData(String recvData) throws InvalidAlgorithmParameterException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException { //서버로부터 오는 메시지 활용
        // 여기부터 3EPROTO 패킷 처리를 개시합니다.
        String[] arr=recvData.split("\n");
        if(arr[0].equals("3EPROTO ACCEPT")){ //사용자가 로그인 성공하였으면
            recvData=clientContext.getId()+"님 로그인 되었습니다!";
        }
        else if(arr[0].equals("3EPROTO DENY")){
            recvData=arr[3];
        }
        else if(arr[0].equals("3EPROTO RELAYOK")){
            recvData=clientContext.getFriendId()+"님이 정상적으로 키를 받으셨습니다.";
        }
        else if(arr[0].equals("3EPROTO KEYXCHGOK")){
            recvData=clientContext.getFriendId()+"님이 정상적으로 키를 받으셨습니다.";
        }
        else if(arr[0].equals("3EPROTO KEYXCHGFAIL")){
            recvData=clientContext.getFriendId()+"님이 키를 받지 못하셨습니다.\n"+arr[4];
        }
        else if(arr[0].equals("3EPROTO KEYXCHG")){ //키 교환하는 것이면
            if(arr.length==7){ //공개키교환하는 것이면
                clientContext.setChatterPublickKey(arr[6]);
                recvData=clientContext.getFriendId()+"님으로부터 공개키를 받으셨습니다.";
                System.out.println("키 받음");
            }
            else if(arr.length==8) { //대칭키와 IV교환
                clientContext.setKeyIv(recvData, arr[6], arr[7]);
                recvData=clientContext.getFriendId()+"님으로부터 키와 IV를 받으셨습니다.";
                System.out.println("대칭키, IV교환");
            }
        }
        else if(arr[0].equals("3EPROTO KEYXCHGRST")){ //새로운 대칭암호키와 IV로 바꾸는 것이면
            clientContext.setKeyIv(recvData, arr[6], arr[7]);
            System.out.println("새로운 대칭암호키와 IV로 바꾸는 것");
            recvData=clientContext.getFriendId()+"님으로부터 키와 IV를 받으셨습니다.";
        }
        else if(arr[0].equals("3EPROTO MSGRECV")){
            recvData=clientContext.recvDecodeM(recvData);
        }
        else if(arr[0].equals("3EPROTO BYE")){
            recvData="로그아웃 되었습니다.";
        }
        else if(arr[0].equals("3EPROTO MSGSENDOK")){
            recvData=clientContext.getFriendId()+"님이 메시지를 받으셨습니다.";
        }
        clientContext.txtFromServer("\n==== recv ====\n"+recvData +"\n");
    }
}