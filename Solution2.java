
//reading console
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;

//reading files
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;

//encryption
import java.security.*;

class Key{
    BigInteger value1;
    BigInteger value2;

    public Key(String value1, String value2){
        this.value1 = new BigInteger(value1);
        this.value2 = new BigInteger(value2);
    }

    public BigInteger e(){
        return value1;
    }

    public BigInteger d(){
        return value1;
    }

    public BigInteger n(){
        return value2;
    }
}

class Solution2 {
    // key generations fucntion. Should be probabilistic (different every time)
    public static void KeyGen(int bitLength) throws NoSuchAlgorithmException, IOException {
        //random genorator
        SecureRandom random = new SecureRandom();

        //first randomize p and q for bitlength.
        BigInteger p = new BigInteger("1");
        BigInteger q = new BigInteger("1");

        //loop until p and q are unique primes
        while(p.equals(q)){
            p = BigInteger.probablePrime(bitLength, random);
            q = BigInteger.probablePrime(bitLength, random);
        }

        //n = pq
        BigInteger n = p.multiply(q);

        //φ(n) = (p-1)(q-1)
        BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        //e ∈ {1,...,φ(n)} where gcd(e, φ(n)) = 1
        BigInteger e = new BigInteger("1");
        BigInteger d = e.modInverse(phiN);

        while(true){
            e = e.add(BigInteger.ONE);
            if(e.gcd(phiN).equals(BigInteger.ONE)){
                d = e.modInverse(phiN);
                if(e.multiply(d).mod(phiN).equals(BigInteger.ONE.mod(phiN))){
                    break;
                }
            }
        }
        
        // output public key (e, n) to pk.txt
        FileWriter file = new FileWriter("pk.txt");
        file.write(e.toString()+"\n"+n.toString());
        file.close();

        // output private key (d, n) to sk.txt
        file = new FileWriter("sk.txt");
        file.write(d.toString()+"\n"+n.toString());
        file.close();
    }

    // RSA Signing function
    public static void Sign(Key sk, int m) throws IOException {
        //convert m to bigint
        BigInteger m_bigInt = BigInteger.valueOf(m);

        //extract d and n from private key
        /* temp values */
        BigInteger d = sk.d();
        BigInteger n = sk.n();

        //calculatge sign
        BigInteger s = m_bigInt.modPow(d, n);

        //write to file
        FileWriter file = new FileWriter("sig.txt");
        file.write(s.toString());
        file.close();
    }

    // RSA verification function
    public static void Verify(Key pk, BigInteger s, int m) {
        //extract e and n from public key
        BigInteger e = pk.e();
        BigInteger n = pk.n();

        //convert m to bigint
        BigInteger m_bigInt = BigInteger.valueOf(m);

        //verify
        if(m_bigInt.equals(s.modPow(e, n))){
            System.out.println("True");
        } else {
            System.out.println("False");
        }
    }

    public static void main(String args[]) throws IOException, NoSuchAlgorithmException {
        //common variables
        int m = 0;

        //buffer readers
        //I dont know if there is a better way to do this but im really unfamiliar with java
        BufferedReader br = null;
        BufferedReader sk_br = null;
        BufferedReader m_br = null;
        BufferedReader pk_br = null;
        BufferedReader s_br = null;

        // menu
        while (true) {
            // display
            System.out.println("------------------------------------");
            System.out.println("RSA Signiture");
            System.out.println("1. KeyGen");
            System.out.println("2. Sign");
            System.out.println("3. Verify");
            System.out.println("4. Exit");
            System.out.println("------------------------------------");
            System.out.print("selection: ");

            br = new BufferedReader(new InputStreamReader(System.in));
            String input = br.readLine();

            // selection
            if (input.equals("1")) {
                // KeyGen
                System.out.print("Bitlength between 10 and 30: ");
                input = br.readLine();

                if(Integer.parseInt(input) > 10 && Integer.parseInt(input) < 30){
                    KeyGen(Integer.parseInt(input));
                    System.out.println("done.");
                } else {
                    System.out.println("Bad input");
                }
                
            } else if (input.equals("2")) {
                //sign
                //files
                File sk_file = new File("sk.txt");

                File m_file = new File("mssg.txt");

                //check files are there
                if(!m_file.exists() || !sk_file.exists()){
                    System.out.println("Missing file.");
                    break;
                }

                //buffer readers
                sk_br = new BufferedReader(new FileReader(sk_file));
                m_br = new BufferedReader(new FileReader(m_file));

                //read sk
                Key sk = new Key(sk_br.readLine(), sk_br.readLine());

                //read m
                try{
                    m = Integer.parseInt(m_br.readLine());
                }catch (NumberFormatException e){
                    System.out.println("m in mssg.txt is not an integer");
                    break;
                }

                Sign(sk, m);

                sk_br.close();
                m_br.close();

                System.out.println("done.");
            } else if(input.equals("3")) {
                //Verify
                File pk_file = new File("pk.txt");
                File s_file = new File("sig.txt");

                //check files are there
                if(!pk_file.exists() || !s_file.exists()){
                    System.out.println("Missing file.");
                    break;
                }
                
                pk_br = new BufferedReader(new FileReader(pk_file));
                Key pk = new Key(pk_br.readLine(), pk_br.readLine());                

                s_br = new BufferedReader(new FileReader(s_file));
                BigInteger s = new BigInteger(s_br.readLine());                

                Verify(pk, s, m);

                pk_br.close();
                s_br.close();
            } else if(input.equals("4")) {
                //exit
                System.out.println("bye");
                return;
            } else {
                //input error
                System.out.println("Please only enter single number corsiponding to menu option");
            }
        }

        br.close();
    }
}









