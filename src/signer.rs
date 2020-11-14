use byteorder::{LittleEndian, WriteBytesExt};
use num_bigint::traits::ModInverse;
use num_bigint::BigUint;
use rsa::{Hash, PaddingScheme, PublicKeyParts, RSAPrivateKey};
use std::convert::TryInto;

pub struct RsaKey {
    private_key: RSAPrivateKey,
}

// openssl genrsa -out priv.pem 2048
pub const DEFAULT_PRIV_KEY: &'static str = r"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4Dyn85cxDJnjM
uYXQl/w469MDKdlGdviLfmFMWeYLVfL2Mz1AVyvKqscrtlhbbgMQ/M+3lDvEdHS0
14RIGAwWRtrlTTmhLvM2/IO+eSKSYeCrCVc4KLG3E3WRryUXbs2ynA29xjTJVw+Z
xYxDyn/tAYPEyMm4v+HIJHcOtRzxtO2vjMJ2vBT/ywYxjhncXbFSO09q2E4XrHli
SIPyO82hZgCkpzTZRp+nyA17TYuV9++mvUr9lWH9RbC+o8EF3yitlBsE2uXr97EV
i2Qy8CE7FIxsihXlukppwKRuz+1rJrvmZPTn49ZS+sIS99WE9GoCpsyQvTpvehrM
SIDRsVZPAgMBAAECggEAWNXAzzXeS36zCSR1yILCknqHotw86Pyc4z7BGUe+dzQp
itiaNIaeNTgN3zQoGyDSzA0o+BLMcfo/JdVrHBy3IL1cAxYtvXTaoGxp7bGrlPk2
pXZhqVJCy/jRYtokzdWF5DHbk/+pFJA3kGE/XKzM54g2n/DFI61A/QdUiz2w1ZtI
vc5cM08EM8B/TSI3SeWB8zkh5SlIuLsFO2J2+tCak6PdFfKOVIrFv9dKJYLxx+59
+edZamw2EvNlnl/sewgUk0gaZvQKVf4ivHyM+KSHuV4RFfiLvGuVcyA6XhSjztsG
EA++jDHP5ib/Izes7UK09v9y7kow+z6vUtnDDQOvgQKBgQD8WWAn7FQt9aziCw19
gZynzHG1bXI7uuEVSneuA3UwJImmDu8W+Qb9YL9Dc2nV0M5pGGdXKi2jzq8gPar6
GPAmy7TOlov6Nm0pbMXTAfuovG+gIXxelp3US3FvyRupi0/7UQRRwvetFYbDFwJX
ydF5uEtZdGSHAjPeU5FLq6tBwQKBgQC6uN0JwwZn+eaxguyKOXvp0KykhFI0HI1A
MBDZ1uuKt6OW5+r9NeQtTLctGlNKVQ8wz+Wr0C/nLGIIv4lySS9WFyc5/FnFhDdy
LsEi6whcca4vq3jsMOukvQGFnERsou4LqBEI1Es7jjeeEq+/8WnNTi6Y1flZ6UAp
YAOeFI98DwKBgQDvyfHgHeajwZalOQF5qGb24AOQ9c4dyefGNnvhA/IgbCfMftZc
iwhETuGQM6R3A7KQFRtlrXOu+2BYD6Ffg8D37IwD3vRmL7+tJGoapwC/B0g+7nLi
4tZY+9Nv+LbrdbDry8GB+/UkKJdk3IFicCk4M5KOD1bTH5mwAtLHB/p1QQKBgDHi
k8M45GxA+p4wMUvYgb987bLiWyfq/N3KOaZJYhJkb4MwoLpXfIeRuFqHbvsr8GwF
DwIxE6s6U1KtAWaUIN5qPyOhxMYdRcbusNDIZCp2gKfhsuO/SiVwDYkJr8oqWVip
5SsrtJHLtBY6PdQVBkRAf/h7KiwYQfkL2suQCKmHAoGBAJAkYImBYPHuRcnSXikn
xGDK/moPvzs0CjdPlRcEN+Myy/G0FUrOaC0FcpNoJOdQSYz3F6URA4nX+zj6Ie7G
CNkECiepaGyquQaffwR1CAi8dH6biJjlTQWQPFcCLA0hvernWo3eaSfiL7fHyym+
ile69MHFENUePSpuRSiF3Z02
-----END PRIVATE KEY-----";

impl RsaKey {
    pub fn from_pkcs8(pkcs8_content: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let der_encoded = pkcs8_content
            .lines()
            .filter(|line| !line.starts_with("-") && !line.is_empty())
            .fold(String::new(), |mut data, line| {
                data.push_str(&line);
                data
            });
        let der_bytes = base64::decode(&der_encoded)?;
        let private_key = RSAPrivateKey::from_pkcs8(&der_bytes)?;

        Ok(RsaKey { private_key })
    }

    pub fn encoded_public_key(&self) -> Result<String, Box<dyn std::error::Error>> {
        // see https://android.googlesource.com/platform/system/core/+/android-4.4_r1/adb/adb_auth_host.c
        // L63 RSA_to_RSAPublicKey
        const RSANUMBYTES: u32 = 256;
        const RSANUMWORDS: u32 = 64;
        if self.private_key.size() != RSANUMBYTES as usize {
            return Err("RSA key must be 2048 bits".into());
        }

        let mut result = vec![];
        result.write_u32::<LittleEndian>(RSANUMWORDS).unwrap();
        let r32 = set_bit(32);
        let n = self.private_key.n();
        let r = set_bit((32 * RSANUMWORDS) as _);
        let rr = r.modpow(&BigUint::from(2u32), n);
        let rem = n % &r32;
        let n0inv = rem.mod_inverse(&r32);
        if let Some(n0inv) = n0inv {
            let n0inv = n0inv.to_biguint().unwrap();
            let n0inv_p: u32 =
                1 + !u32::from_le_bytes((&n0inv.to_bytes_le()[..4]).try_into().unwrap());
            result.write_u32::<LittleEndian>(n0inv_p).unwrap();
        } else {
            return Err("Mod inverse is ill-defined".into());
        }

        write_biguint(&mut result, n, RSANUMBYTES as _);
        write_biguint(&mut result, &rr, RSANUMBYTES as _);
        write_biguint(&mut result, self.private_key.e(), 4);

        let mut encoded = base64::encode(&result);
        encoded.push_str(" webadb@browser");
        Ok(encoded)
    }

    pub fn sign(&self, msg: impl AsRef<[u8]>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.private_key
            .sign(
                PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA1)),
                msg.as_ref(),
            )
            .map_err(|e| e.into())
    }
}

fn write_biguint(mut writer: &mut [u8], data: &BigUint, n_bytes: usize) {
    for &v in data
        .to_bytes_le()
        .iter()
        .chain(std::iter::repeat(&0))
        .take(n_bytes)
    {
        writer.write_u8(v).unwrap();
    }
}

fn set_bit(n: usize) -> BigUint {
    BigUint::parse_bytes(
        &{
            let mut bits = vec![];
            bits.push(b'1');
            for _ in 0..n {
                bits.push(b'0');
            }
            bits
        }[..],
        2,
    )
    .unwrap()
}
