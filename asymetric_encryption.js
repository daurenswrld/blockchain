class RSASingleton {
    constructor() {
        if (!RSASingleton.instance) {
            RSASingleton.instance = this;
        }
        return RSASingleton.instance;
    }

    gcd(a, b) {
        while (b != 0) {
            let t = b;
            b = a % b;
            a = t;
        }
        return a;
    }

    modInverse(e, phi) {
        for (let i = 1; i < phi; i++) {
            if ((e * i) % phi === 1) {
                return i;
            }
        }
        return null;
    }

    isPrime(num) {
        for (let i = 2; i <= Math.sqrt(num); i++) {
            if (num % i === 0) return false;
        }
        return num > 1;
    }

    generateKeypair(p, q) {
        if (!this.isPrime(p) || !this.isPrime(q)) return null;
        if (p === q) return null;

        const n = p * q;
        const phi = (p - 1) * (q - 1);

        let e = Math.floor(Math.random() * (phi - 1)) + 1;
        let g = this.gcd(e, phi);
        while (g !== 1) {
            e = Math.floor(Math.random() * (phi - 1)) + 1;
            g = this.gcd(e, phi);
        }

        const d = this.modInverse(e, phi);

        return {
            publicKey: { e, n },
            privateKey: { d, n }
        };
    }

    encrypt({ e, n }, msg) {
        const msgCodes = msg.split('').map(c => c.charCodeAt());
        return msgCodes.map(code => BigInt(code) ** BigInt(e) % BigInt(n));
    }

    decrypt({ d, n }, encryptedMsg) {
        return encryptedMsg.map(code => String.fromCharCode(Number(BigInt(code) ** BigInt(d) % BigInt(n)))).join('');
    }

    hash(message) {
        return message.split('').reduce((acc, char) => (acc * 31 + char.charCodeAt(0)) % 65536, 0);
    }

    sign(privateKey, message) {
        const messageHash = this.hash(message);
        return BigInt(messageHash) ** BigInt(privateKey.d) % BigInt(privateKey.n);
    }

    verify(publicKey, message, signature) {
        const messageHash = this.hash(message);
        const decryptedHash = Number(BigInt(signature) ** BigInt(publicKey.e) % BigInt(publicKey.n));
        return messageHash === decryptedHash;
    }
}

const instance = new RSASingleton();
Object.freeze(instance);

const { publicKey, privateKey } = instance.generateKeypair(61, 53); // Use two prime numbers
const message = "Hi";
const signature = instance.sign(privateKey, message);

console.log("Message:", message);
console.log("Signature:", signature.toString());

const isValid = instance.verify(publicKey, message, signature);
console.log("Is the signature valid?", isValid);

