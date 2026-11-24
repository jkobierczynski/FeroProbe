//! Big numbers for the NSE compatibility layer's `openssl.bignum_*`
//! (roadmap 7.6): arbitrary-precision integers on `num-bigint`, with the
//! calls nmap documents (conversions, addition, division, modular
//! exponentiation, bits, primality and random numbers). Written for
//! FeroProbe from nmap's public API documentation.
//!
//! Every size is capped, so one call cannot hold a script for long:
//! numbers of at most [`MAX_BITS`] bits, modular exponentiation and
//! primality tests on at most [`MAX_EXP_BITS`] bits.

use mlua::{Lua, MetaMethod, Table, UserData, UserDataMethods, UserDataRef, UserDataRefMut};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};

/// Largest number a script may build or grow to.
pub(crate) const MAX_BITS: u64 = 65536;
/// Largest modulus or exponent of `bignum_mod_exp`, and largest number
/// `bignum_is_prime` tests: some tenths of a second of work at most.
pub(crate) const MAX_EXP_BITS: u64 = 16384;

/// A big number as a Lua value.
#[derive(Clone, Debug)]
pub(crate) struct Bn(pub BigInt);

impl UserData for Bn {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::ToString, |_, this, ()| Ok(this.0.to_string()));
        methods.add_meta_method(MetaMethod::Eq, |_, this, other: UserDataRef<Bn>| {
            Ok(this.0 == other.0)
        });
    }
}

fn err<T>(msg: impl Into<String>) -> mlua::Result<T> {
    Err(mlua::Error::runtime(msg.into()))
}

fn checked(n: BigInt, what: &str) -> mlua::Result<Bn> {
    if n.bits() > MAX_BITS {
        return err(format!(
            "openssl.{what}: numbers of more than {MAX_BITS} bits are not available in FeroProbe"
        ));
    }
    Ok(Bn(n))
}

/// Parse `text` in `radix` with an optional leading `-`, as OpenSSL's
/// BN_dec2bn and BN_hex2bn take it.
fn parse(text: &str, radix: u32, what: &str) -> mlua::Result<Bn> {
    let (neg, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    if digits.is_empty() || digits.len() as u64 > MAX_BITS / 3 {
        return err(format!("openssl.{what}: not a number: {text:?}"));
    }
    let Some(mag) = BigUint::parse_bytes(digits.as_bytes(), radix) else {
        return err(format!("openssl.{what}: not a number: {text:?}"));
    };
    let sign = if neg && !mag.is_zero() {
        Sign::Minus
    } else {
        Sign::Plus
    };
    checked(BigInt::from_biguint(sign, mag), what)
}

fn bit_index(pos: i64, what: &str) -> mlua::Result<u64> {
    match u64::try_from(pos) {
        Ok(p) if p < MAX_BITS => Ok(p),
        _ => err(format!("openssl.{what}: bit position {pos} out of range")),
    }
}

/// Small primes for trial division before Miller-Rabin.
fn small_primes() -> impl Iterator<Item = u32> {
    (3u32..2000).step_by(2).filter(|n| {
        (3..)
            .step_by(2)
            .take_while(|d| d * d <= *n)
            .all(|d| n % d != 0)
    })
}

/// Miller-Rabin rounds for a false-positive rate below 2^-80, by size
/// (the bounds of the Handbook of Applied Cryptography, table 4.4).
fn rounds(bits: u64) -> u32 {
    match bits {
        b if b >= 3747 => 3,
        b if b >= 1345 => 4,
        b if b >= 476 => 5,
        b if b >= 400 => 6,
        b if b >= 347 => 7,
        b if b >= 308 => 8,
        b if b >= 55 => 27,
        _ => 34,
    }
}

fn random_below(limit: &BigUint) -> Option<BigUint> {
    // Uniform in [0, limit): draw as many bytes as the limit has, with a
    // margin, and reduce; the bias is below 2^-64.
    let bytes = super::digest::random(limit.to_bytes_be().len() + 8)?;
    Some(BigUint::from_bytes_be(&bytes) % limit)
}

/// Probably prime: trial division, then Miller-Rabin with random bases.
/// `None` when no random bytes are available.
pub(crate) fn is_probable_prime(n: &BigUint) -> Option<bool> {
    let two = BigUint::from(2u32);
    if *n < two {
        return Some(false);
    }
    for p in std::iter::once(2u32).chain(small_primes()) {
        let p = BigUint::from(p);
        if *n == p {
            return Some(true);
        }
        if (n % &p).is_zero() {
            return Some(false);
        }
    }
    let one = BigUint::one();
    let n1 = n - &one;
    let s = n1.trailing_zeros().unwrap_or(0);
    let d = &n1 >> s;
    let n3 = n - 3u32;
    'rounds: for _ in 0..rounds(n.bits()) {
        let a = random_below(&n3)? + &two;
        let mut x = a.modpow(&d, n);
        if x == one || x == n1 {
            continue;
        }
        for _ in 1..s {
            x = x.modpow(&two, n);
            if x == n1 {
                continue 'rounds;
            }
        }
        return Some(false);
    }
    Some(true)
}

fn prime_check(n: &BigInt, what: &str) -> mlua::Result<Option<BigUint>> {
    if n.bits() > MAX_EXP_BITS {
        return err(format!(
            "openssl.{what}: numbers of more than {MAX_EXP_BITS} bits are not tested in FeroProbe"
        ));
    }
    Ok(n.to_biguint())
}

fn no_random<T>() -> mlua::Result<T> {
    err("no random bytes available")
}

/// Fill `t` (the `openssl` module's table) with the `bignum_*` calls.
pub(crate) fn install(lua: &Lua, t: &Table) -> mlua::Result<()> {
    let ud = |lua: &Lua, b: Bn| lua.create_userdata(b);
    t.raw_set(
        "bignum_bin2bn",
        lua.create_function(move |lua, s: mlua::LuaString| {
            let b = s.as_bytes();
            if b.len() as u64 * 8 > MAX_BITS {
                return err(format!(
                    "openssl.bignum_bin2bn: numbers of more than {MAX_BITS} bits are not available in FeroProbe"
                ));
            }
            ud(lua, Bn(BigInt::from_bytes_be(Sign::Plus, &b)))
        })?,
    )?;
    t.raw_set(
        "bignum_dec2bn",
        lua.create_function(move |lua, s: String| ud(lua, parse(&s, 10, "bignum_dec2bn")?))?,
    )?;
    t.raw_set(
        "bignum_hex2bn",
        lua.create_function(move |lua, s: String| ud(lua, parse(&s, 16, "bignum_hex2bn")?))?,
    )?;
    t.raw_set(
        "bignum_bn2bin",
        lua.create_function(|lua, a: UserDataRef<Bn>| {
            // The magnitude, big-endian, without leading zeros (zero is
            // the empty string), as BN_bn2bin.
            let (_, mag) = a.0.to_bytes_be();
            if a.0.is_zero() {
                lua.create_string("")
            } else {
                lua.create_string(mag)
            }
        })?,
    )?;
    t.raw_set(
        "bignum_bn2dec",
        lua.create_function(|_, a: UserDataRef<Bn>| Ok(a.0.to_str_radix(10)))?,
    )?;
    t.raw_set(
        "bignum_bn2hex",
        lua.create_function(|_, a: UserDataRef<Bn>| Ok(a.0.to_str_radix(16).to_uppercase()))?,
    )?;
    t.raw_set(
        "bignum_add",
        lua.create_function(move |lua, (a, b): (UserDataRef<Bn>, UserDataRef<Bn>)| {
            ud(lua, checked(&a.0 + &b.0, "bignum_add")?)
        })?,
    )?;
    t.raw_set(
        "bignum_div",
        lua.create_function(move |lua, (a, b): (UserDataRef<Bn>, UserDataRef<Bn>)| {
            if b.0.is_zero() {
                return err("openssl.bignum_div: division by zero");
            }
            // Truncating division, as BN_div: the remainder has the
            // dividend's sign.
            let q = &a.0 / &b.0;
            let r = &a.0 % &b.0;
            Ok((ud(lua, Bn(q))?, ud(lua, Bn(r))?))
        })?,
    )?;
    t.raw_set(
        "bignum_mod_exp",
        lua.create_function(
            move |lua, (a, p, m): (UserDataRef<Bn>, UserDataRef<Bn>, UserDataRef<Bn>)| {
                if m.0.is_zero() {
                    return err("openssl.bignum_mod_exp: modulus is zero");
                }
                if p.0.is_negative() {
                    return err("openssl.bignum_mod_exp: negative exponent");
                }
                if m.0.bits() > MAX_EXP_BITS || p.0.bits() > MAX_EXP_BITS {
                    return err(format!(
                        "openssl.bignum_mod_exp: numbers of more than {MAX_EXP_BITS} bits are not available in FeroProbe"
                    ));
                }
                let m = m.0.abs();
                // A non-negative result below |m|, as BN_mod_exp.
                let base = ((&a.0 % &m) + &m) % &m;
                ud(lua, Bn(base.modpow(&p.0, &m)))
            },
        )?,
    )?;
    t.raw_set(
        "bignum_num_bits",
        lua.create_function(|_, a: UserDataRef<Bn>| Ok(a.0.bits()))?,
    )?;
    t.raw_set(
        "bignum_num_bytes",
        lua.create_function(|_, a: UserDataRef<Bn>| Ok(a.0.bits().div_ceil(8)))?,
    )?;
    t.raw_set(
        "bignum_is_bit_set",
        lua.create_function(|_, (a, pos): (UserDataRef<Bn>, i64)| {
            Ok(match u64::try_from(pos) {
                Ok(p) => a.0.magnitude().bit(p),
                Err(_) => false,
            })
        })?,
    )?;
    t.raw_set(
        "bignum_set_bit",
        lua.create_function(|_, (mut a, pos): (UserDataRefMut<Bn>, i64)| {
            let p = bit_index(pos, "bignum_set_bit")?;
            let (sign, mut mag) = (a.0.sign(), a.0.magnitude().clone());
            mag.set_bit(p, true);
            a.0 = BigInt::from_biguint(
                if sign == Sign::Minus {
                    Sign::Minus
                } else {
                    Sign::Plus
                },
                mag,
            );
            Ok(())
        })?,
    )?;
    t.raw_set(
        "bignum_clear_bit",
        lua.create_function(|_, (mut a, pos): (UserDataRefMut<Bn>, i64)| {
            let p = bit_index(pos, "bignum_clear_bit")?;
            let (sign, mut mag) = (a.0.sign(), a.0.magnitude().clone());
            mag.set_bit(p, false);
            a.0 = BigInt::from_biguint(sign, mag);
            Ok(())
        })?,
    )?;
    t.raw_set(
        "bignum_is_prime",
        lua.create_function(|_, a: UserDataRef<Bn>| {
            let Some(n) = prime_check(&a.0, "bignum_is_prime")? else {
                return Ok(false);
            };
            is_probable_prime(&n).map_or_else(no_random, Ok)
        })?,
    )?;
    t.raw_set(
        "bignum_is_safe_prime",
        lua.create_function(|_, a: UserDataRef<Bn>| {
            let Some(n) = prime_check(&a.0, "bignum_is_safe_prime")? else {
                return Ok((false, false));
            };
            let Some(prime) = is_probable_prime(&n) else {
                return no_random();
            };
            if !prime || n < BigUint::from(5u32) {
                return Ok((false, prime));
            }
            let half = (&n - 1u32) >> 1;
            match is_probable_prime(&half) {
                Some(safe) => Ok((safe, true)),
                None => no_random(),
            }
        })?,
    )?;
    let rand = lua.create_function(move |lua, bits: i64| {
        let bits = match u64::try_from(bits) {
            Ok(b) if b <= MAX_BITS => b,
            _ => return err(format!("openssl.bignum_rand: {bits} bits out of range")),
        };
        if bits == 0 {
            return ud(lua, Bn(BigInt::zero()));
        }
        let Some(bytes) = super::digest::random(bits.div_ceil(8) as usize) else {
            return no_random();
        };
        // Exactly `bits` bits long: the extra high bits cleared, the top
        // one set.
        let mut n = BigUint::from_bytes_be(&bytes);
        let excess = bits.div_ceil(8) * 8 - bits;
        if excess > 0 {
            n &= (BigUint::one() << bits) - 1u32;
        }
        n.set_bit(bits - 1, true);
        ud(lua, Bn(BigInt::from(n)))
    })?;
    t.raw_set("bignum_rand", rand.clone())?;
    t.raw_set("bignum_pseudo_rand", rand)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primes() {
        let p = |s: &str| BigUint::parse_bytes(s.as_bytes(), 10).unwrap();
        for n in [
            "2",
            "3",
            "5",
            "1999",
            "2003",
            "1000000007",
            "170141183460469231731687303715884105727",
        ] {
            assert_eq!(is_probable_prime(&p(n)), Some(true), "{n}");
        }
        // 561 and 41041 are Carmichael numbers; the last is 2^127+1.
        for n in [
            "0",
            "1",
            "4",
            "561",
            "41041",
            "1000000008",
            "170141183460469231731687303715884105729",
        ] {
            assert_eq!(is_probable_prime(&p(n)), Some(false), "{n}");
        }
        // RFC 3526's 2048-bit MODP group prime is a safe prime.
        let modp = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
            16,
        )
        .unwrap();
        assert_eq!(is_probable_prime(&modp), Some(true));
        assert_eq!(is_probable_prime(&((&modp - 1u32) >> 1)), Some(true));
        assert_eq!(rounds(2048), 4);
    }
}
