# Threshold Paillier Homomorphic encryption system 



Main methods: 

For 3-out-of-5 threshold, below is the procedure and test code:

- c = publicKey.encrypt(x)
- c1 = privKey1.partialDecrypt(c)
- c2 = privKey2.partialDecrypt(c)
- c3 = privKey3.partialDecrypt(c)


result = combineShares([c1, c2, c3], publicKey)

assert(result == x)


```
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

```

### key generation

You only need to generate the random numbers that satisfying the below conditions, then the code will produce the private keys and public key.
```
 assert (p1.isProbablePrime(100) && q1.isProbablePrime(100)
                && p.isProbablePrime(100) && q.isProbablePrime(100));
```

Thank you and enjoy!  :)
