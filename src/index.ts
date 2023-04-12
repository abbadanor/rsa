import { bigintToText, textToBigint } from 'bigint-conversion';
import {
  gcd, lcm, modInv, modPow, randBetween,
} from 'bigint-crypto-utils';
import { generatePrime as generatePrimecb } from 'node:crypto';
import { promisify } from 'node:util';

/**
 * A version of node:crypto's generatePrime function that returns a promise
 *
 * @param size - The size (in bits) of the prime to generate.
 *
 * @returns A promise of a prime BigInt
 */
const generatePrime = promisify((
  size: number,
  cb: (err: Error, prime: bigint) => void,
) => generatePrimecb(size, { bigint: true }, cb));

interface PublicKey {
  readonly n: bigint
  readonly e: bigint
}

interface PrivateKey {
  readonly d: bigint
  readonly n: bigint
}

interface CipherText {
  text: bigint
  isString: boolean
}

class RSA {
  /**
    * Skapar en instans av klassen RSA
    *
    * @param publicKey - Består av talen e och n
    * @param privateKey - Består av talen p, q och d
    */
  constructor(
    readonly publicKey: PublicKey,
    private privateKey: PrivateKey,
  ) {}

  /**
   * p, q - Random large primes, should be kept secret.
   * n - The modulus for both the public and private.
   * Released as part of the public and private key.
   * lambda - The smallest possible integer that fulfills aᵐ ≡ (mod n). Should be kept secret.
   * e - Coprime with lambda. The most commonly chosen value is 65 537. Smaller values are faster
   * but less secure. Released as part of the public key.
   * d - The modular multiplicative inverse of e modulo lambda.
   * It is kept secret as the private key exponent.
   *
   * @param bitLength - The size (in bits) to generate the keys.
   * @param e - Randomly chosen if no value is given. 65 537 is the most commonly
   * chosen value.
   * Higher is more secure but more demanding.
   */
  static async generateKeyPair(bitLength = 2048, e?: bigint) {
    const p = await generatePrime(bitLength);

    let q: bigint;

    do {
      // eslint-disable-next-line no-await-in-loop
      q = await generatePrime(bitLength);
    } while (q === p);

    const n = p * q;

    const lambda = lcm(p - 1n, q - 1n);

    if (e === undefined) {
      do {
        e = randBetween(lambda, 3n);
      } while (gcd(e, lambda) !== 1n);
    }

    const d = modInv(e, lambda);

    const publicKey = { n, e };
    const privateKey = { d, n };
    return new RSA(publicKey, privateKey);
  }

  decrypt(cipher: CipherText) {
    if (cipher.isString) {
      return bigintToText(modPow(cipher.text, this.privateKey.d, this.privateKey.n));
    }
    return modPow(cipher.text, this.privateKey.d, this.privateKey.n);
  }

  sign(message: string): CipherText {
    const msgInt = textToBigint(message);
    return {
      text: modPow(msgInt, this.privateKey.d, this.privateKey.n),
      isString: true,
    };
  }

  static verify(signature: CipherText, publicKey: PublicKey) {
    return bigintToText(modPow(signature.text, publicKey.e, publicKey.n));
  }

  static encrypt(m: string | bigint, publicKey: PublicKey): CipherText {
    if (typeof m === 'string') {
      return {
        text: modPow(textToBigint(m), publicKey.e, publicKey.n),
        isString: true,
      };
    }
    return {
      text: modPow(m, publicKey.e, publicKey.n),
      isString: false,
    };
  }
}

async function main() {
  const A = await RSA.generateKeyPair();
  const B = await RSA.generateKeyPair(2048, 65_537n);

  const c1 = RSA.encrypt('hej', B.publicKey); // Alice meddelande till Bob krypteras med Bobs offentliga nyckel
  console.log(B.decrypt(c1)); // Bob dekrypterar chifferkoden med sin privata nyckel.

  const c2 = RSA.encrypt(1488n, A.publicKey);
  console.log(A.decrypt(c2));

  const s1 = A.sign('Alice signatur');
  const v1 = RSA.verify(s1, A.publicKey);
  console.log(v1);
}

// eslint-disable-next-line @typescript-eslint/no-floating-promises
main();
