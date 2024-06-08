package HE;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class TestThresPaillier {

    public static void main(String[] args) {
        Random random = new Random();
        for(int i = 0; i < 100; i++){
            ThresholdPaillier thp = new ThresholdPaillier(1024, 3, 3);
            BigInteger v = new BigInteger(200, random);
            v = v.multiply(BigInteger.valueOf(-1)).mod(thp.n);
            List<ThresholdPaillier.TPPrivKey> privKeyList = thp.privKeys;
            ThresholdPaillier.TPPublicKey pubKey = thp.publicKey;
            ThresholdPaillier.EncryptedNumber c = pubKey.encrypt(v);

            ThresholdPaillier.Share share1 = privKeyList.get(0).partialDecrypt(c);
            ThresholdPaillier.Share share2 = privKeyList.get(1).partialDecrypt(c);
            ThresholdPaillier.Share share3 = privKeyList.get(2).partialDecrypt(c);
            List<ThresholdPaillier.Share> shares = new ArrayList<>();
            shares.add(share1);
            shares.add(share2);
            shares.add(share3);
            BigInteger result = ThresholdPaillier.combineShares(shares, pubKey);
//            System.out.println("result = " + result);
            assert (v.compareTo(result) == 0);

        }
        System.out.println("First test case passed");
        {
            for(int i = 0; i < 100; i++){
                ThresholdPaillier thp = new ThresholdPaillier(1024, 3, 3);
                BigInteger v = new BigInteger(200, random);
                v = v.multiply(BigInteger.valueOf(-1)).mod(thp.n);

                BigInteger v2 = new BigInteger(50, random);

                List<ThresholdPaillier.TPPrivKey> privKeyList = thp.privKeys;
                ThresholdPaillier.TPPublicKey pubKey = thp.publicKey;
                ThresholdPaillier.EncryptedNumber c = pubKey.encrypt(v);
                c = c.mul(v2);

                ThresholdPaillier.Share share1 = privKeyList.get(0).partialDecrypt(c);
                ThresholdPaillier.Share share2 = privKeyList.get(1).partialDecrypt(c);
                ThresholdPaillier.Share share3 = privKeyList.get(2).partialDecrypt(c);
                List<ThresholdPaillier.Share> shares = new ArrayList<>();
                shares.add(share1);
                shares.add(share2);
                shares.add(share3);
                BigInteger result = ThresholdPaillier.combineShares(shares, pubKey);
//                System.out.println("result = " + result);
                assert (v.multiply(v2).mod(thp.n).compareTo(result) == 0);
            }
            System.out.println("Second test case passed");
        }
        {
            {
                for(int i = 0; i < 100; i++){
                    ThresholdPaillier thp = new ThresholdPaillier(1024, 3, 5);
                    BigInteger v = new BigInteger(200, random);
                    BigInteger v2 = new BigInteger(50, random);
                    List<ThresholdPaillier.TPPrivKey> privKeyList = thp.privKeys;
                    ThresholdPaillier.TPPublicKey pubKey = thp.publicKey;
                    ThresholdPaillier.EncryptedNumber c = pubKey.encrypt(v);
                    ThresholdPaillier.EncryptedNumber c2 = pubKey.encrypt(v2);
                    ThresholdPaillier.EncryptedNumber c3 = c.add(c2);

                    ThresholdPaillier.Share share1 = privKeyList.get(0).partialDecrypt(c3);
                    ThresholdPaillier.Share share2 = privKeyList.get(1).partialDecrypt(c3);
                    ThresholdPaillier.Share share3 = privKeyList.get(2).partialDecrypt(c3);
                    List<ThresholdPaillier.Share> shares = new ArrayList<>();
                    shares.add(share2);
                    shares.add(share1);

                    shares.add(share3);
                    BigInteger result = ThresholdPaillier.combineShares(shares, pubKey);
//                    System.out.println("result = " + result);
                    assert (v.add(v2).mod(thp.n).compareTo(result) == 0);
                }
                System.out.println("Three test case passed");
            }
        }
    }
}
