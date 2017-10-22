package pl.dimzi.aesbrutus;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainFrame extends JFrame implements ActionListener {
    JLabel cipherLabel;
    JTextField cipherTextField;
    JLabel ivLabel;
    JTextField ivTextField;
    JLabel keySuffixLabel;
    JTextField keySuffixTextField;
    JLabel rangeByteLabel;
    JLabel startByteLabel;
    JTextField startByteTextField;
    JLabel stopByteLabel;
    JTextField stopByteTextField;
    JLabel threadsLabel;
    JTextField threadsTextField;
    JTextArea logTextArea;
    JButton startButton;
    JButton stopButton;

    JTextField[] keyTextField;

    Thread[] thread;

    public MainFrame(){
        super("AES-Breaker");
        setPreferredSize(new Dimension(600, 700));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setResizable(false);

        setLayout(new FlowLayout());

        cipherLabel = new JLabel("Szyfrogram");
        cipherTextField = new JTextField();
        ivLabel = new JLabel("IV");
        ivTextField = new JTextField();
        keySuffixLabel = new JLabel("Suffix klucza");
        keySuffixTextField = new JTextField();

        rangeByteLabel = new JLabel("Przedział przeszukiwań 0-255");
        startByteLabel = new JLabel("Start");
        startByteTextField = new JTextField();
        stopByteLabel = new JLabel("Stop");
        stopByteTextField = new JTextField();

        threadsLabel = new JLabel("Liczba wątków");
        threadsTextField = new JTextField();

        startButton = new JButton("Start");
        startButton.setActionCommand("start");
        startButton.addActionListener(this);

        stopButton = new JButton("stop");
        stopButton.setActionCommand("stop");
        stopButton.addActionListener(this);

        cipherLabel.setPreferredSize(new Dimension(100, 30));
        cipherTextField.setPreferredSize(new Dimension(400, 30));
        ivLabel.setPreferredSize(new Dimension(100, 30));
        ivTextField.setPreferredSize(new Dimension(400, 30));
        keySuffixLabel.setPreferredSize(new Dimension(100, 30));
        keySuffixTextField.setPreferredSize(new Dimension(400, 30));

        rangeByteLabel.setPreferredSize(new Dimension(200, 30));
        startByteLabel.setPreferredSize(new Dimension(50, 30));
        startByteTextField.setPreferredSize(new Dimension(100, 30));
        stopByteLabel.setPreferredSize(new Dimension(50, 30));
        stopByteTextField.setPreferredSize(new Dimension(100, 30));

        threadsLabel.setPreferredSize(new Dimension(100, 30));
        threadsTextField.setPreferredSize(new Dimension(100, 30));

        logTextArea = new JTextArea();
        logTextArea.setEditable(false);
        logTextArea.setLineWrap(true);

        JScrollPane scroll = new JScrollPane(logTextArea);
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        scroll.setPreferredSize(new Dimension(500, 300));

        File data = new File("dane.txt");
        if(data.exists() && !data.isDirectory()){
            try {
                Scanner s = new Scanner(data);
                String line = s.nextLine();
                cipherTextField.setText(line.split("[ ]+")[1]);
                line = s.nextLine();
                System.out.println(Arrays.toString(line.split("[ ]+")));
                ivTextField.setText(line.split("[ ]+")[1]);
                line = s.nextLine();
                keySuffixTextField.setText(line.split("[ ]+")[1]);
            }catch(Exception e){}
        } else {
            cipherTextField.setText("FuHtl4nCjRlPe5/WkK+vKeI8t5HvYUeJDdpasuG4hnnwLhCZP9nP5iyHikt7lAqA7QbzhT/V5qUAL6n2/zhd8Xcv2Eduhr4JzcTLa+ZCnLuatQOet5obos4XAOZJguPQeOFuDeI+L29j8H61QKAgWQ==");
            ivTextField.setText("732d66f3b31277fba1edfb8a114fc73a");
            keySuffixTextField.setText("3d6c89b1349b6a9756460747ead00c4f9b8adefd9c52f27deed3fa9a36");
        }
        startByteTextField.setText("0");
        stopByteTextField.setText("0");
        threadsTextField.setText("1");

        add(cipherLabel);
        add(cipherTextField);
        add(ivLabel);
        add(ivTextField);
        add(keySuffixLabel);
        add(keySuffixTextField);
        add(rangeByteLabel);
        add(startByteLabel);
        add(startByteTextField);
        add(stopByteLabel);
        add(stopByteTextField);
        add(threadsLabel);
        add(threadsTextField);
        add(startButton);
        add(stopButton);
        add(scroll);

        pack();

        setVisible(true);
    }


    @Override
    public void actionPerformed(ActionEvent e) {
        if(e.getActionCommand().equals("start")){
            startButton.setEnabled(false);
            start();
        } else if(e.getActionCommand().equals("stop")){
            stop();
        }
    }

    private void stop(){
        try {
            for (Thread thread : this.thread) {
                thread.interrupt();
                thread.join();
            }
        } catch(InterruptedException e) {
        }
        startButton.setEnabled(true);
    }

    private void start() {
        clearlog();
        if(keyTextField != null){
            for(int i = 0; i < keyTextField.length; ++i){
                remove(keyTextField[i]);
            }
        }

        try {
            String cipherText = cipherTextField.getText();
            String ivText = ivTextField.getText();
            String suffixText = keySuffixTextField.getText();

            int suffixLength = (suffixText.length() + 1) / 2;

            System.out.println("Suffix text length: " + suffixText.length());

            final int unknownPartLength = (256 - suffixText.length() * 4);
            log("Do zdekodowania " + unknownPartLength + " bitów, czyli " + unknownPartLength / 8.0 + " bajtów");

            boolean byteUpper = suffixText.length() % 2 == 1;

            System.out.println("Byte upper: " + byteUpper);

            final byte[] encodedValue = Base64.getDecoder().decode(cipherText);
            final byte[] ivValue = trim((new BigInteger(ivText, 16)).toByteArray(), (ivText.length() + 1) / 2);
            final byte[] suffixValue = trim((new BigInteger(suffixText, 16)).toByteArray(), suffixLength);

            System.out.println("Suffix length: " + suffixLength);
            System.out.println("Suffix: " + Arrays.toString(suffixValue));

            final byte start = (byte)Integer.parseInt(startByteTextField.getText());
            final byte stop = (byte)Integer.parseInt(stopByteTextField.getText());

            byte[] singleStartKeyValue = makeKey(suffixValue, byteUpper, 0, start);

            System.out.println("Make key length: " + singleStartKeyValue.length);
            System.out.println("Make key: " + Arrays.toString(singleStartKeyValue));

            try {
                //cipher test
                IvParameterSpec iv = new IvParameterSpec(ivValue);
                Key key = new SecretKeySpec(singleStartKeyValue, "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, key, iv);
                cipher.doFinal(encodedValue);
            }catch(BadPaddingException e){}

            final int threads = Integer.parseInt(threadsTextField.getText());

            log("Tworzenie wątków");

            keyTextField = new JTextField[threads];
            thread = new Thread[threads];
            for(int i = 0; i < threads; ++i){
                keyTextField[i] = new JTextField();
                keyTextField[i].setEditable(false);
                keyTextField[i].setPreferredSize(new Dimension(550, 30));
                keyTextField[i].setFont(new Font(Font.MONOSPACED, Font.BOLD, 14));

                add(keyTextField[i]);
                pack();
                setVisible(true);

                final int threadNum = i;
                thread[i] = new Thread(() -> decrypt(encodedValue, ivValue, suffixValue, byteUpper, start, stop, threadNum, threads));
            }

            log("Startowanie wątków");
            for(int i = 0; i < threads; ++i) {
                thread[i].start();
            }
        } catch(Exception e){
            log("Starting error");
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String exceptionAsString = sw.toString();
            log(exceptionAsString.split("\n")[0]);
            startButton.setEnabled(true);
        }
    }

    private void decrypt(byte[] encodedValue, byte[] ivValue, byte[] suffixValue, boolean byteUpper, byte start, byte stop, int thread, int threads){
        byte[] tmp = new byte[encodedValue.length];
        System.arraycopy(encodedValue, 0, tmp, 0, encodedValue.length);
        encodedValue = tmp;
        
        tmp = new byte[ivValue.length];
        System.arraycopy(ivValue, 0, tmp, 0, ivValue.length);
        ivValue = tmp;
        
        tmp = new byte[suffixValue.length];
        System.arraycopy(suffixValue, 0, tmp, 0, suffixValue.length);
        suffixValue = tmp;
        
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            Pattern textPattern = Pattern.compile("^[\\p{L}\\s0-9.,!\"#%&'()*+_:;<=>?-{}]+$");
            Matcher matcher = textPattern.matcher("");

            byte[] keyValue = makeKey(suffixValue, byteUpper, thread, start);

            long loops = 0;

            while(true){
                if(Thread.currentThread().isInterrupted()){
                    break;
                }
                //printKeyValue(keyValue, thread);
                if(loops == 22222){
                    printKeyValue(keyValue, thread);
                    loops = 0;
                }
                loops++;

                IvParameterSpec iv = new IvParameterSpec(ivValue);
                Key key = new SecretKeySpec(keyValue, "AES");
                cipher.init(Cipher.DECRYPT_MODE, key, iv);
                try{
                    String decrypted = new String(cipher.doFinal(encodedValue), "UTF-8");
                    matcher.reset(decrypted);
                    if(matcher.matches()) {
                        log("ODSZYFROWANO!");
                        log(new BigInteger(key.getEncoded()).toString(16));
                        log(decrypted);
                        File file = new File("decrypted.txt");
                        file.createNewFile();
                        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file, true), StandardCharsets.UTF_8));
                        writer.write(new BigInteger(key.getEncoded()).toString(16));
                        writer.newLine();
                        writer.write(decrypted);
                        writer.newLine();
                        writer.close();
                    }
                }catch(BadPaddingException e){}

                byte firstByteBefore = keyValue[0];
                increaseByteArray(keyValue, suffixValue, byteUpper, thread, threads);
                if(firstByteBefore != keyValue[0] && keyValue[0] == stop){
                    break;
                }
            }
            printKeyValue(keyValue, thread);
        }catch(Exception e){
            log("Wątek " + thread + " błąd: " + e.getMessage());
        }
        log("Wątek " + thread + " zakończony");
    }

    private void printKeyValue(byte[] keyValue, int thread){
        final StringBuilder builder = new StringBuilder();
        for(byte b : keyValue) {
            builder.append(String.format("%02x", b));
        }

        keyTextField[thread].setText(builder.toString());
    }

    public void increaseByteArray(byte[] keyValue, byte[] suffixValue, boolean byteUpper, final int thread, final int threads){
        final int bytesNeeded = 32 - suffixValue.length;
        int startByte;
        if(!byteUpper)
            startByte = bytesNeeded - 1;
        else
            startByte = bytesNeeded;
        int i = startByte;
        while(i >= 0) {
            //System.out.println("thread " + thread + " - arr[" + i + "] = " + arr[i] + " = " + Integer.toBinaryString(arr[i]) + " | " + Integer.toBinaryString((byte)((0x000000FF & arr[i])>>4)) + " = " + ((byte)((0x000000FF & arr[i])>>4)));
            if (i == startByte) {
                if(byteUpper){
                    keyValue[i] += threads * 0x10;
                    //overflow, go to next byte
                    if((byte)((0x000000FF & keyValue[i])>>4) == thread){
                        --i;
                    } else {
                        break;
                    }
                } else {
                    keyValue[i] += threads;
                    if(keyValue[i] == thread){
                        --i;
                    } else {
                        break;
                    }
                }
            } else {
                keyValue[i]++;
                //overflow, go to next byte
                if(keyValue[i] == 0){
                    --i;
                } else {
                    break;
                }
            }
        }
    }

    private byte[] makeKey(byte[] suffix, boolean byteUpper, int threadStart, byte start) throws Exception{
        final int bytesNeeded = 32 - suffix.length;

        if(bytesNeeded < 0 || (bytesNeeded == 0 && !byteUpper)){
            log(bytesNeeded + " " + byteUpper);
            throw new Exception("Bad suffix");
        }

        byte[] keyValue = new byte[32];
        System.arraycopy(suffix, 0, keyValue, bytesNeeded, suffix.length);

        if(byteUpper == false){
            keyValue[bytesNeeded - 1] += threadStart;
        } else {
            keyValue[bytesNeeded] += threadStart * 0x10;
        }

        keyValue[0] += start;

        return keyValue;
    }

    private byte[] trim(byte[] array, int length){
        if(array.length > length){
            byte[] tmp = new byte[length];
            System.arraycopy(array, array.length - length, tmp, 0, length);
            array = tmp;
        } else if(array.length < length){
            byte[] tmp = new byte[length];
            System.arraycopy(array, 0, tmp, length - array.length, array.length);
            array = tmp;
        }
        return array;
    }

    private void clearlog(){
        logTextArea.setText("");
    }

    private void log(String str){
        Calendar cal = Calendar.getInstance();
        Date date = cal.getTime();
        DateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
        String formattedDate = dateFormat.format(date);
        logTextArea.setText(logTextArea.getText() + "log " + formattedDate + " >" + str + "\r\n");
    }
}
