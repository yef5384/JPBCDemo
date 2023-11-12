import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class BLSDemo {
    public static void main(String[] args){
        //初始化
        //1、生成paring参数对<G1,GT,Zr,g,e>
        Pairing bp = PairingFactory.getPairing("a.properties");
        Field G1 = bp.getG1();
        Field GT = bp.getGT();
        Field Zr = bp.getZr();
        Element g = G1.newRandomElement().getImmutable();
        Element e = bp.pairing(g,g);
        //2、选取x∈Zr作为私钥
        Element x = Zr.newRandomElement().getImmutable();
        //3、计算g的x次方作为公钥
        Element g_x = g.powZn(x);

        //签名
        String m = "hello!";
        byte[] m_hash = Integer.toString(m.hashCode()).getBytes();
        Element h = G1.newElementFromBytes(m_hash);
        Element sig = h.duplicate().powZn(x);

        //验证
        if(bp.pairing(sig,g).isEqual(bp.pairing(h,g_x)))
            System.out.println("yes");
        else
            System.out.println("no");
    }
}
