// Protocol RSPEQ

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_os::OsRng;

use crate::petpit::{rando};

// ElGamal encryption with randomness r
pub fn rspeq_enc(pk: (RistrettoPoint,RistrettoPoint), m: RistrettoPoint, r:Scalar)
        -> (RistrettoPoint,RistrettoPoint){
    (r*pk.1 + m, r*pk.0)
}

//First move
pub fn rspeq_flow_1 (pk0: (RistrettoPoint,RistrettoPoint),pk1: (RistrettoPoint,RistrettoPoint), c0: (RistrettoPoint,RistrettoPoint), c1: (RistrettoPoint,RistrettoPoint))
        -> ((RistrettoPoint,RistrettoPoint),(RistrettoPoint,RistrettoPoint),RistrettoPoint,Scalar,Scalar) {
    let mut rng = OsRng::new().unwrap();
    let r_1 = Scalar::random(&mut rng);
    let r_2 = Scalar::random(&mut rng);

    let rm = RistrettoPoint::random(&mut rng);

    (rando(pk0,(c0.0+rm,c0.1),r_1),rando(pk1,(c1.0+rm,c1.1),r_2),rm,r_1,r_2)
}
//Second move
pub fn rspeq_flow_2 () -> bool {
    return rand::random();
}
//Third move
pub fn rspeq_flow_3 (b: bool, r0: Scalar,r_0: Scalar, r1: Scalar, r_1: Scalar) -> (Scalar,Scalar) {
    if b {
        (r_0,r_1)
    }
    else
    {
        (r0+r_0,r1+r_1)
    }
}
//Fourth move
pub fn rspeq_flow_4 (b: bool, pk0: (RistrettoPoint,RistrettoPoint),pk1: (RistrettoPoint,RistrettoPoint),c0: (RistrettoPoint,RistrettoPoint),c_0: (RistrettoPoint,RistrettoPoint),c1: (RistrettoPoint,RistrettoPoint), c_1: (RistrettoPoint,RistrettoPoint),rx: Scalar, ry: Scalar, rm: RistrettoPoint) -> bool {
    if b {
        let c00 = rando(pk0,(c0.0+rm,c0.1),rx);
        let c11 = rando(pk1,(c1.0+rm,c1.1),ry);
        c_0 == c00 && c_1 == c11
    }
    else
    {
        c_0.0-(rx*pk0.1) == c_1.0-(ry*pk1.1)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::petpit::{crs_gen};

    fn rspeq_key_init_test(should_succeed: bool) -> bool{
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
    fn rspeq_ki_success() {
        assert_eq!(rspeq_key_init_test(true), true);
    }

    #[test]
    fn rspeq_ki_fail() {
        assert_eq!(rspeq_key_init_test(false), false);
    }

    fn do_fast_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (pk0,_) = crs_gen();
        let (pk1,_) = crs_gen();
        let m0= Scalar::zero() * pk0.0;
        let mut m1 = Scalar::one() * pk0.1;
        if should_succeed {
            m1 = m0
        }

        let mut rng = OsRng::new().unwrap();
        let r0 = Scalar::random(&mut rng);
        let r1 = Scalar::random(&mut rng);

        let c0 = rspeq_enc(pk0, m0,r0);
        let c1 = rspeq_enc(pk1, m1,r1);

        let mut bo = true;
        let mut i = 0;
        while i < 128 && bo {

            let (c_0,c_1,rm,r_0,r_1) = rspeq_flow_1(pk0,pk1,c0,c1);

            let b = rspeq_flow_2();

            let (rx,ry) = rspeq_flow_3(b,r0,r_0,r1,r_1);

            bo = rspeq_flow_4(b,pk0,pk1,c0,c_0,c1,c_1,rx,ry,rm);

            i = i+1;
        }
        bo
    }

    #[test]
    fn success() {
        assert_eq!(do_fast_test(true), true);
    }

    #[test]
    fn fail() {
        assert_eq!(do_fast_test(false), false);
    }
}
