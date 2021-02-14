// Public Key Generation with verifiable randomness

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_os::OsRng;

use crate::petpit::{rando};



// picks a cipher, and sends it randomization
pub fn eq_flow_1 (pk: (RistrettoPoint,RistrettoPoint), c0: (RistrettoPoint,RistrettoPoint), c1: (RistrettoPoint,RistrettoPoint), b: bool)
        -> ((RistrettoPoint,RistrettoPoint),RistrettoPoint,Scalar) {
    let mut rng = OsRng::new().unwrap();
    let r = Scalar::random(&mut rng);
    let rm = RistrettoPoint::random(&mut rng);

    if b {
        (rando(pk,(c1.0+rm,c1.1),r),rm,r)
    }
    else
    {
        (rando(pk,(c0.0+rm,c0.1),r),rm,r)
    }
}


// returns the offset
pub fn eq_flow_2f (sk: Scalar, c0: (RistrettoPoint,RistrettoPoint), cb: (RistrettoPoint,RistrettoPoint))
        -> RistrettoPoint {
            (cb.0 - c0.0) - sk * (cb.1 - c0.1)

}

// Does the answer match the challenge?
pub fn eq_flow_3f(rm:RistrettoPoint, z:RistrettoPoint)
        -> bool
{
    rm==z
}


// Slow Prot :
pub fn eq_flow_2s (sk: Scalar, c0: (RistrettoPoint,RistrettoPoint), cb: (RistrettoPoint,RistrettoPoint))
        -> (RistrettoPoint,Scalar) {
        let z = (cb.0 - c0.0) - sk * (cb.1 - c0.1);
        let mut rng = OsRng::new().unwrap();
        let s = Scalar::random(&mut rng);

        (s*z,s)

}

pub fn eq_flow_3s (_: RistrettoPoint, r:Scalar, rm:RistrettoPoint)
        -> (Scalar,RistrettoPoint) {
            (r,rm)

        }

pub fn eq_flow_4s (pk: (RistrettoPoint,RistrettoPoint),r:Scalar, rm:RistrettoPoint, s:Scalar, c0:(RistrettoPoint,RistrettoPoint),c1:(RistrettoPoint,RistrettoPoint),cb:(RistrettoPoint,RistrettoPoint))
        -> Scalar {
     if rando(pk,(c1.0+rm,c1.1),r) != cb && rando(pk,(c0.0+rm,c0.1),r) != cb {
         r
     }
     else {
        s
    }

 }

pub fn eq_flow_5s (cz:RistrettoPoint, s:Scalar,rm:RistrettoPoint)
        -> bool {
    s*rm == cz
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::petpit::{crs_gen, enc};

    fn eqdo_key_init_test(should_succeed: bool) -> bool{
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
    fn eqki_success() {
        assert_eq!(eqdo_key_init_test(true), true);
    }

    #[test]
    fn eqki_fail() {
        assert_eq!(eqdo_key_init_test(false), false);
    }

    fn eq_do_fast_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (pk,sk) = crs_gen();
        let m0= Scalar::zero() * pk.0;
        let mut m1 = Scalar::one() * pk.1;
        if should_succeed {
            m1 = m0
        }

        let c0 = enc(pk, m0);
        let c1 = enc(pk, m1);

        let mut bo = true;
        let mut i = 0;
        while i < 128 && bo {
            let b = rand::random();

            let (cb,rm,_) = eq_flow_1(pk,c0,c1,b);

            let z = eq_flow_2f(sk,c0,cb);

            bo=eq_flow_3f(rm,z);
            i = i+1;
        }
        bo
    }


    #[test]
    fn fast_success() {
        assert_eq!(eq_do_fast_test(true), true);
    }

    #[test]
    fn fast_fail() {
        assert_eq!(eq_do_fast_test(false), false);
    }

    fn eq_do_slow_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (pk,sk) = crs_gen();
        let m0 = Scalar::zero() * pk.0;
        let mut m1 = Scalar::one() * pk.1;
        if should_succeed {
            m1 = m0
        }

        let c0 = enc(pk, m0);
        let c1 = enc(pk, m1);

        let mut bo = true;
        let mut i = 0;
        while i < 128 && bo {
            let b = rand::random();

            let (cb,rm,r) = eq_flow_1(pk,c0,c1,b);

            let (cz,s) = eq_flow_2s(sk,c0,cb);

            let (ra,rma) = eq_flow_3s(cz,r, rm);

            let sa = eq_flow_4s(pk,ra,rma,s,c0,c1,cb);

            bo = eq_flow_5s(cz,sa,rm);
            i = i+1;
        }
        bo
    }


    #[test]
    fn slow_success() {
        assert_eq!(eq_do_slow_test(true), true);
    }

    #[test]
    fn slow_fail() {
        assert_eq!(eq_do_slow_test(false), false);
    }



}
