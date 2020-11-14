use rsa::{Hash, PaddingScheme, RSAPrivateKey};
use sha1::{Digest, Sha1};

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
        let pubkey = rsa_export::pkcs8::public_key(&self.private_key.to_public_key())?;
        Ok(base64::encode(pubkey))
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

/*
// test fails
#[test]
fn test_encode_decode() {
    // openssl genrsa -out priv.pem 2048
    let privkey = r"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQClnrfgGadJV7M5
ebamGf4Is8+VA3vFZZ7dgV9BDRMqCOqKflYkoZgdsq3z/cSHsQg/rfpftefMcZmV
4kqumCCawtjdqwN2LwEY6IPILU0UmEZjcJmhgJShMXGUobiHxl0RUn2qt8KUi/A7
eYnuCy4gq0vNKRZqvZXEMd+eqCq3AFNKY5I1fvbmcYgK5AeNJSy4GpZ1qPFWkkMl
RW6Odo9pXnWlUO1WlLTwvtaO/uvlgQ+Wrsey/U84K7HDVgSi6GXGUd5zcBH0QzaR
JVc0X6OuBj5jF6Hi6LVlGmmrh5LDJBYe00kDlLEachPKJtD0HgQBsPopFLAtDrKk
bIGv9s0dAgMBAAECggEAEaZAYhlZwm8eIlneJQVQFQ1UacTdQ8P4khJfXEdQa4JX
vDqKY4z08PVBpGa+stci0eZwcBKqiRbyDw72dnSvxM5O3hCDZezMaSMeKA7rz+4K
Uj6FoLhbHnJucDBrwcxZzqbDzZWXnszq5Oumzz9Rwxl+Enb2dJmPhEDsW7QAGVA7
o/H/N+B0GCNqjsMo1WsnQZf4+G3cBxl8ayO5qJmEtg/ZKT12/EzXLqHOkt6jt8++
OWM+kneRvAhTM5fOhq3ISBCi+Yixj81NDphC82+mJ23gHn1x/CsZcoKALBmLtKdH
23jnlbDGiKynoqHZYBm/srxR0aHlhxLJpPx0h6N6AQKBgQDWZGWVeh9ELmRc55Jd
kTQu6GLqMV8Y9ahgphNj1eiSTM78U4RnRJuaLAPeFFUe0Ujh/27pKFN5eg8Q29aw
hZiuvXuUlNXOOyisIAL1u+wltjceh/36YoekR3TkqfHNkbFdfFqh/uWrU7nuHERB
7Pcmv85eDlw3a2IkvbRtQJgk8QKBgQDFwy7Xtvy66HRKb1ouzSt36096ZqQAE+HW
mP7XidAREUAIrMEUOkzYE0hqYPXNbdMU6sUApD5avglNeuM/Dn3Kwrf5JgTkG6yw
trsaXtgEA2QblyhMiZOXghVwh9OmwxRs4JxQ21LKMe3Mj1Vcz+hpQzRB3GrLHzTi
qAj1fp467QKBgGU3vxIENxC8ilumZN7R9/4Rbum8Z3ZkPJtsrQjca9Hue2Z7k64h
oQj3sNe/Z7SGAE/ahaWEiWx3qPc/oytx13TgNqEeZ5bXLUueTWdw0nu3fGxorgrx
S7LOnax7Y5K3LzLAzBVhP1NU0xpMtBkf5EuiEK8tPnJXu103RyCxd2MxAoGAVqMu
l1RUHfIOWDm2MYCyxWNyOzZSLLKJIsF+C6EVZRTAj8xW/eyYk6TG+cumg6vUaHp9
ec16f7h3TNlESvCnTTfG70CnreMt4XD8QQ5B5mgx6CBtiDJRVXOovtbSc2FNRnGU
KZwcBfafrhkxFWsD73GAqEXPB1ORkKZ63kntOfUCgYBcDsiu9A0f5Y1AVFuIzvEA
mXzcMYEQrkfoc+yI0vPZwRzTJHmp92y8DotaI2JHXVNa4E1mKiKiG6jFkhnuuU9C
jfdNkt2VY2nyX88BdutwFUn7CG2K8/LqQ0BrJS1Nkqn7Z/UB+4ko5nye/hP2RFhG
gq7n9FHm98RZL3aTSpIj5w==
-----END PRIVATE KEY-----";

    let pubkey = r"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApZ634BmnSVezOXm2phn+
CLPPlQN7xWWe3YFfQQ0TKgjqin5WJKGYHbKt8/3Eh7EIP636X7XnzHGZleJKrpgg
msLY3asDdi8BGOiDyC1NFJhGY3CZoYCUoTFxlKG4h8ZdEVJ9qrfClIvwO3mJ7gsu
IKtLzSkWar2VxDHfnqgqtwBTSmOSNX725nGICuQHjSUsuBqWdajxVpJDJUVujnaP
aV51pVDtVpS08L7Wjv7r5YEPlq7Hsv1POCuxw1YEouhlxlHec3AR9EM2kSVXNF+j
rgY+Yxeh4ui1ZRppq4eSwyQWHtNJA5SxGnITyibQ9B4EAbD6KRSwLQ6ypGyBr/bN
HQIDAQAB"
        .lines()
        .collect::<String>();

    assert_eq!(
        RsaKey::from_pkcs8(privkey)
            .unwrap()
            .encoded_public_key()
            .unwrap(),
        pubkey
    )
}
*/
