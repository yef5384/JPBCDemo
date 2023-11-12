import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.util.Base64;
import java.util.Properties;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class IBE {
    public static void savePropToFile(Properties prop,String fileName){
        try(FileOutputStream outputStream = new FileOutputStream(fileName)) {
            prop.store(outputStream,null);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + "save failed!");
            System.exit(-1);
        }
    }
    public static Properties loadPropFromFile(String fileName){
        Properties prop = new Properties();
        try(FileInputStream inputStream = new FileInputStream(fileName)){
            prop.load(inputStream);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + "read failed!");
            System.exit(-1);
        }
        return prop;
    }
    public static void setUp(String paramFileName,String pkFileName,String mskFileName){
        Pairing bp = PairingFactory.getPairing(paramFileName);
        Field G1 = bp.getG1();
        Field Zr = bp.getZr();

        Properties mskProp = new Properties();
        Element x = Zr.newRandomElement().getImmutable();
        mskProp.setProperty("x",Base64.getEncoder().encodeToString(x.toBytes()));
        savePropToFile(mskProp,mskFileName);

        Properties pkProp = new Properties();
        Element g = G1.newRandomElement().getImmutable();
        Element gx = g.powZn(x).getImmutable();
        pkProp.setProperty("g",Base64.getEncoder().encodeToString(g.toBytes()));
        pkProp.setProperty("gx",Base64.getEncoder().encodeToString(gx.toBytes()));
        savePropToFile(pkProp,pkFileName);
    }
    public static void keyGen(String paramFileName,String id,String mskFileName,String skFileName) throws NoSuchAlgorithmException{
        Pairing bp = PairingFactory.getPairing(paramFileName);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] id_hash = sha256.digest(id.getBytes());
        Element QID = bp.getG1().newElementFromBytes(id_hash).getImmutable();

        Properties pkProp = loadPropFromFile(mskFileName);
        String xString = pkProp.getProperty("x");
        Element x = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xString)).getImmutable();
        Element sk = QID.powZn(x).getImmutable();

        Properties skProp = new Properties();
        skProp.setProperty("sk", Base64.getEncoder().encodeToString(sk.toBytes()));
        savePropToFile(skProp,skFileName);
    }
    public static void encrypt(String paramFileName,String id,String message,String pkFileName,String cFileName) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        Pairing bp = PairingFactory.getPairing(paramFileName);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] id_hash = sha256.digest(id.getBytes());
        Element QID = bp.getG1().newElementFromBytes(id_hash).getImmutable();

        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String gxString = pkProp.getProperty("gx");
        Element gx = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gxString)).getImmutable();
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element C1 = g.powZn(r).getImmutable();
        Element gID = bp.pairing(QID,gx).powZn(r).getImmutable();
        byte[] gIDByte = sha256.digest(gID.toBytes());
        byte[] messageByte = message.getBytes();
        byte[] C2 = new byte[message.length()];
        for (int i=0;i<messageByte.length;i++){
            C2[i] = (byte)(messageByte[i] ^ gIDByte[i]);
        }

        Properties cProp = new Properties();
        cProp.setProperty("C1",Base64.getEncoder().encodeToString(C1.toBytes()));
        cProp.setProperty("C2",Base64.getEncoder().encodeToString(C2));
        savePropToFile(cProp,cFileName);
    }
    public static String decrypt(String paramFileName,String skFileName,String cFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(paramFileName);

        Properties cProp = loadPropFromFile(cFileName);
        String C1String = cProp.getProperty("C1");
        Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1String)).getImmutable();
        Properties skProp = loadPropFromFile(skFileName);
        String skString = skProp.getProperty("sk");
        Element sk = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skString)).getImmutable();

        Element gID = bp.pairing(sk,C1).getImmutable();

        String C2String = cProp.getProperty("C2");
        byte[] C2 = Base64.getDecoder().decode(C2String);

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] HgID = sha256.digest(gID.toBytes());
        byte[] messageByte = new byte[C2.length];
        for (int i=0;i<messageByte.length;i++){
            messageByte[i] = (byte)(C2[i]^HgID[i]);
        }
        return new String(messageByte);
    }
    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String idBob = "Bob123456";
        String message = "hi,i'm Bob!";

        String paramFileName = "a.properties";

        String dir = "data/";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String cFileName = dir + "c.properties";

        setUp(paramFileName,pkFileName,mskFileName);
        keyGen(paramFileName,idBob,mskFileName,skFileName);
        encrypt(paramFileName,idBob,message,pkFileName,cFileName);
        String res = decrypt(paramFileName,skFileName,cFileName);
        System.out.println(res);
    }
}
