

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ThresholdPaillier {
    BigInteger n;

    public List<TPPrivKey> privKeys;
    public TPPublicKey publicKey;

    public ThresholdPaillier(int sizeOfN, int T, int N){
        //bit length of n is 1024
        BigInteger p1 = new BigInteger("8739239105101534846934875027967706598723158329205866780591960404043153202325462791805090719407848667133750422150377528730073841567599406780489076059788341");
        BigInteger q1 = new BigInteger("9886980368060885826600852778990346259032250462293771873677702172383965574788498778017808735171751855492970553322013161149504945203878453909563272675229661");

        BigInteger p = p1.multiply(BigInteger.TWO).add(BigInteger.ONE);
        BigInteger q = q1.multiply(BigInteger.TWO).add(BigInteger.ONE);

        assert (p1.isProbablePrime(100) && q1.isProbablePrime(100)
                && p.isProbablePrime(100) && q.isProbablePrime(100));

        this.n = p.multiply(q);
        int s = 1;
        BigInteger ns = n.pow(s);
        BigInteger nSPlusOne = n.pow(s + 1);
        BigInteger nSquare = n.multiply(n);
        BigInteger m = p1.multiply(q1);
        BigInteger nm = n.multiply(m);
        int l = N;
        int w = T;
        int delta = factorial(l);
        Random random = new Random();
        BigInteger combineSharesConstant = BigInteger.valueOf(4).multiply(BigInteger.valueOf(delta * delta)).mod(n).modInverse(n);
        BigInteger d = m.multiply(m.modInverse(n));
        List<BigInteger> ais = new ArrayList<>();
        ais.add(d);
        for(int i = 1; i < w; i++){
            ais.add(new BigInteger(nm.bitLength()-1, random));
        }
        BigInteger r = new BigInteger(p.bitLength()-1, random);
        while(r.gcd(n).compareTo(BigInteger.ONE) != 0){
            r = new BigInteger(p.bitLength()-1, random);
        }
        BigInteger v = r.multiply(r).mod(nSquare);
        BigInteger[] si = new BigInteger[l];
        BigInteger[] viarray = new BigInteger[l];
        for(int i = 0; i < l; i++){
            si[i] = BigInteger.ZERO;
            viarray[i] = BigInteger.ZERO;
        }
        for(int i = 0; i < l; i++){
            BigInteger X = BigInteger.valueOf(i).add(BigInteger.ONE);
            for(int j = 0; j < w; j++){
                BigInteger temp = ais.get(j).multiply(X.pow(j));
                si[i] = si[i].add(temp);
            }
            si[i] = si[i].mod(nm);
            viarray[i] = v.modPow(si[i].multiply(BigInteger.valueOf(delta)), nSquare);
        }
        this.privKeys = new ArrayList<>();
        for(int i = 0; i < l; i++){
            this.privKeys.add(new TPPrivKey(n, l, combineSharesConstant, w, v, viarray, si[i],
                    i + 1, r, delta, nSPlusOne));
        }
        this.publicKey = new TPPublicKey(n, nSPlusOne, r, ns, w, delta, combineSharesConstant);
    }

    private int factorial(int n){
        int fact = 1;
        for(int i = 1; i < n + 1; i++){
            fact *= i;
        }
        return fact;
    }

    public class Share{
        int serverID;
        BigInteger v;
        public Share(int serverID, BigInteger v){
            this.serverID = serverID;
            this.v = v;
        }
    }

    public class TPPrivKey{
        private BigInteger n;
        private int l;
        private BigInteger CombineSharesConstant;
        private int w;
        private BigInteger v;
        private BigInteger[] viarray;
        private BigInteger si;
        private int serverID;
        private int delta;
        private BigInteger nSPlusOne;

        private TPPrivKey(BigInteger n, int l, BigInteger combineSharesConstant, int w,
                         BigInteger v, BigInteger[] viarray, BigInteger si,
                         int serverID, BigInteger r, int delta, BigInteger nSPlusOne) {
            this.n = n;
            this.l = l;
            CombineSharesConstant = combineSharesConstant;
            this.w = w;
            this.v = v;
            this.viarray = viarray;
            this.si = si;
            this.serverID = serverID;
            this.delta = delta;
            this.nSPlusOne = nSPlusOne;
        }

        public Share partialDecrypt(EncryptedNumber c){
            BigInteger temp0 = si.multiply(BigInteger.valueOf(2 * delta));
            BigInteger temp = c.c.modPow(temp0, nSPlusOne);
            return new Share(serverID, temp);
        }
    }

    public class TPPublicKey{
        BigInteger n;
        BigInteger nSplusOne;
        BigInteger r;
        BigInteger ns;
        int w;
        int delta;
        BigInteger combineSahresConstant;

        private TPPublicKey(BigInteger n, BigInteger nSplusOne, BigInteger r,
                           BigInteger ns, int w, int delta,
                           BigInteger combineSahresConstant) {
            this.n = n;
            this.nSplusOne = nSplusOne;
            this.r = r;
            this.ns = ns;
            this.w = w;
            this.delta = delta;
            this.combineSahresConstant = combineSahresConstant;
        }

        public EncryptedNumber encrypt(BigInteger msg){
            msg = msg.mod(nSplusOne);
            BigInteger temp = n.add(BigInteger.ONE).modPow(msg, nSplusOne);
            BigInteger temp2 = r.modPow(ns, nSplusOne);
            BigInteger c = temp.multiply(temp2).mod(nSplusOne);
            return new EncryptedNumber(c, nSplusOne, n);
        }
    }

    public class EncryptedNumber{
        BigInteger c;
        BigInteger nSPlusOne;
        BigInteger n;

        private EncryptedNumber(BigInteger c, BigInteger nSPlusOne,
                               BigInteger n) {
            this.c = c;
            this.nSPlusOne = nSPlusOne;
            this.n = n;
        }

        public EncryptedNumber mul(BigInteger constant){
            if(constant.compareTo(BigInteger.ZERO) < 0){
                BigInteger temp = this.c.modInverse(this.nSPlusOne).modPow(constant.abs(), this.nSPlusOne);
                return new EncryptedNumber(temp, this.nSPlusOne, n);
            }else{
                BigInteger temp = this.c.modPow(constant, nSPlusOne);
                return new EncryptedNumber(temp, nSPlusOne, n);
            }
        }

        public EncryptedNumber add(EncryptedNumber ciphertext){
            return new EncryptedNumber(c.multiply(ciphertext.c).mod(nSPlusOne), nSPlusOne, n);
        }
    }

    public static BigInteger combineShares(List<Share> shares, TPPublicKey publicKey){
        return combineShares0(shares, publicKey.w, publicKey.delta, publicKey.combineSahresConstant,
                publicKey.nSplusOne, publicKey.n, publicKey.ns);
    }

    private static BigInteger combineShares0(List<Share> shares, int w, int delta, BigInteger combineSharesConstant, BigInteger nSPlusOne, BigInteger n, BigInteger ns){
        BigInteger cprime = BigInteger.ONE;
        for(int i = 0; i < w; i++){
            int ld = delta;
            for(int iprime = 0; iprime < w; iprime++){
                if(i == iprime) continue;
                if(shares.get(i).serverID != shares.get(iprime).serverID){
                    ld = (ld * (-shares.get(iprime).serverID))/(shares.get(i).serverID - shares.get(iprime).serverID);
                }
            }
            BigInteger shr = ld < 0? shares.get(i).v.modInverse(nSPlusOne): shares.get(i).v;
            ld = ld < 1? (-1 * ld) : ld;
            BigInteger temp = shr.modPow(BigInteger.valueOf(2*ld), nSPlusOne);
            cprime = cprime.multiply(temp).mod(nSPlusOne);
        }
        BigInteger L = cprime.subtract(BigInteger.ONE).divide(n);
        BigInteger result = L.multiply(combineSharesConstant).mod(n);
        return result;
//        return result.mod(ns);
//        return result.compareTo(ns.divide(BigInteger.TWO)) > 0? result.subtract(ns): result;
    }

}




