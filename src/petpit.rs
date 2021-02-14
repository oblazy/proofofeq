// Public Key Generation with verifiable randomness

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_os::OsRng;

// generating an ElGamal key, and sk
pub fn crs_gen()
        -> ((RistrettoPoint, RistrettoPoint),Scalar){
    let mut rng = OsRng::new().unwrap();
    let g = RistrettoPoint::random(&mut rng);
    let sk = Scalar::random(&mut rng);
    let h = sk*g;


    ((g,h),sk)

}

pub fn enc(pk: (RistrettoPoint,RistrettoPoint), m: RistrettoPoint)
        -> (RistrettoPoint,RistrettoPoint){
    let mut rng = OsRng::new().unwrap();
    let r = Scalar::random(&mut rng);
    (r*pk.1 + m, r*pk.0)

}

pub fn rando(pk: (RistrettoPoint,RistrettoPoint), c: (RistrettoPoint,RistrettoPoint), r:Scalar)
        -> (RistrettoPoint,RistrettoPoint){
    (c.0 + r*pk.1, c.1 + r*pk.0)

}

// picks a cipher, and sends it randomization
pub fn flow_1 (pk: (RistrettoPoint,RistrettoPoint), c0: (RistrettoPoint,RistrettoPoint), c1: (RistrettoPoint,RistrettoPoint), b: bool)
        -> ((RistrettoPoint,RistrettoPoint),Scalar) {
    let mut rng = OsRng::new().unwrap();
    let r = Scalar::random(&mut rng);

    if b {
        (rando(pk,c1,r),r)
    }
    else
    {
        (rando(pk,c0,r),r)
    }
}

// Return True if c0 and cb encrypt the same plaintext
pub fn multidec(sk: Scalar, c0: (RistrettoPoint,RistrettoPoint), cb: (RistrettoPoint,RistrettoPoint))
        -> bool {
    (c0.0 - cb.0) == sk*(c0.1 - cb.1)
    }

// Checks if received a randomization of c0 and sends true iff not
pub fn flow_2f (sk: Scalar, c0: (RistrettoPoint,RistrettoPoint), cb: (RistrettoPoint,RistrettoPoint))
        -> bool {
            !(multidec(sk,c0,cb))
}

// Does the answer match the challenge?
pub fn flow_3f(b: bool, z:bool) -> bool
{
    b==z
}

// Checks if received a randomization of c0 and sends true iff not
pub fn flow_2s (sk: Scalar, pk:(RistrettoPoint,RistrettoPoint), c0: (RistrettoPoint,RistrettoPoint), cb: (RistrettoPoint,RistrettoPoint))
        -> (RistrettoPoint,bool,Scalar) {
            let mut rng = OsRng::new().unwrap();
            let s = Scalar::random(&mut rng);
            let z =!(multidec(sk,c0,cb));
            if z{
                (s* pk.0,z,s)
            }
            else {
                (s*pk.0 + pk.1,z,s)
            }
}

pub fn flow_3s (_:RistrettoPoint, r:Scalar)
        -> Scalar {
            r
}

pub fn flow_4s(pk:(RistrettoPoint,RistrettoPoint), cz:(RistrettoPoint,RistrettoPoint), cb:(RistrettoPoint,RistrettoPoint),r: Scalar, s:Scalar)
        -> Scalar {
    if rando(pk, cz, r) == cb {
        s
    }
    else {
        r
    }
}

pub fn flow_ends(pk:(RistrettoPoint,RistrettoPoint), pedz: RistrettoPoint, b:bool, s:Scalar)
        -> bool {
    let f=pedz - s*pk.0;
    (b && f==Scalar::zero()*pk.1) || (!b && f==Scalar::one()*pk.1)
}

// Hash



#[cfg(test)]
mod test {
    use super::*;

    fn do_key_init_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let ((g,h),sk) = crs_gen();

        if should_succeed
        {
            h == sk*g
        }
        else
        {
            h == g
        }
    }


    #[test]
    fn ki_success() {
        assert_eq!(do_key_init_test(true), true);
    }

    #[test]
    fn ki_fail() {
        assert_eq!(do_key_init_test(false), false);
    }

    fn do_fast_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (pk,sk) = crs_gen();
        let m0= Scalar::zero() * pk.0;
        let mut m1 = Scalar::one() * pk.1;
        if !should_succeed {
            m1 = m0
        }

        let c0 = enc(pk, m0);
        let c1 = enc(pk, m1);

        let mut bo = true;
        let mut i = 0;
        while i < 128 && bo {
            let b = rand::random();

            let (cb,_) = flow_1(pk,c0,c1,b);

            let z = flow_2f(sk,c0,cb);

            bo=flow_3f(b,z);
            i = i+1;
        }
        bo
    }


    #[test]
    fn fast_success() {
        assert_eq!(do_fast_test(true), true);
    }

    #[test]
    fn fast_fail() {
        assert_eq!(do_fast_test(false), false);
    }

    fn do_slow_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (pk,sk) = crs_gen();
        let m0 = Scalar::zero() * pk.0;
        let mut m1 = Scalar::one() * pk.1;
        if !should_succeed {
            m1 = m0
        }

        let c0 = enc(pk, m0);
        let c1 = enc(pk, m1);

        let mut bo = true;
        let mut i = 0;
        while i < 128 && bo {
            let b = rand::random();

            let (cb,r) = flow_1(pk,c0,c1,b);

            let (pedz,z,s) = flow_2s(sk,pk,c0,cb);

            let ra = flow_3s(pedz,r);

            let mut cz = c0;
            if z {
                cz=c1;
            }

            let su = flow_4s(pk,cz,cb,ra,s);

            bo=flow_ends(pk,pedz,b,su);
            i = i+1;
        }
        bo
    }


    #[test]
    fn slow_success() {
        assert_eq!(do_slow_test(true), true);
    }

    #[test]
    fn slow_fail() {
        assert_eq!(do_slow_test(false), false);
    }


}
