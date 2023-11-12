import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class JPBCDemo {
    public static void main(String[] args) {
        Pairing bp = PairingFactory.getPairing("a.properties");

        Field G1 = bp.getG1();
        Field Zr = bp.getZr();
        Field GZ = bp.getGT();

        Element g1 = G1.newRandomElement().getImmutable();
        Element g2 = G1.newRandomElement().getImmutable();
        System.out.println(g1.add(g2));
        System.out.println(g1.mul(g2));

        Element a = Zr.newElement(2);
        System.out.println(g1.mul(g1));
        System.out.println(g1.powZn(a));
    }
}