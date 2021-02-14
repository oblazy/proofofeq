// Protocol SIGPEQ

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand_os::OsRng;

use crate::petpit::{rando};

//First move
pub fn sigpeq_flow_1 (pk0: (RistrettoPoint,RistrettoPoint),sk0: Scalar, pk1: (RistrettoPoint,RistrettoPoint),sk1: Scalar, c0: (RistrettoPoint,RistrettoPoint), c1: (RistrettoPoint,RistrettoPoint))
        -> ((RistrettoPoint,RistrettoPoint),(RistrettoPoint,RistrettoPoint),RistrettoPoint,Scalar,Scalar,Scalar,(RistrettoPoint,RistrettoPoint),Scalar,Scalar,(RistrettoPoint,RistrettoPoint),Scalar) {
    let mut rng = OsRng::new().unwrap();
    let r_0 = Scalar::random(&mut rng);
    let r_1 = Scalar::random(&mut rng);
    let rm = RistrettoPoint::random(&mut rng);

    //Randomization of ciphertexts with r and rm
    let c00 = rando(pk0,(c0.0+rm,c0.1),r_0);
    let c11 = rando(pk1,(c1.0+rm,c1.1),r_1);

    //Key randomization
    let rk0 = Scalar::random(&mut rng);
    let rand_pk0 = (pk0.0,pk0.1+(rk0*pk0.0));
    let rand_sk0 = sk0+rk0;

    //Randomization of ciphertexts' key
    let rand_c0 = (c00.0+(rk0*c00.1),c00.1);
  
    let rk1 = Scalar::random(&mut rng);
    let rand_pk1 = (pk1.0,pk1.1+(rk1*pk1.0));
    let rand_sk1 = sk1+rk1;
    let rand_c1 = (c11.0+(rk1*c11.1),c11.1);
    
    (rand_c0,rand_c1,rm,r_0,r_1,rk0,rand_pk0,rand_sk0,rk1,rand_pk1,rand_sk1)
}
//Second move
pub fn sigpeq_flow_2 () -> bool {
    return rand::random();
}
//Third move
pub fn sigpeq_flow_3 (b: bool,rk0: Scalar,rk1: Scalar, rand_sk0: Scalar, rand_sk1: Scalar) -> (Scalar,Scalar) {
    if b {
        (rk0,rk1)
    }
    else
    {
        (rand_sk0,rand_sk1)
    }
}
//Fourth move
pub fn sigpeq_flow_4 (b: bool,pk0: (RistrettoPoint,RistrettoPoint),pk1: (RistrettoPoint,RistrettoPoint),c0: (RistrettoPoint,RistrettoPoint),c_0: (RistrettoPoint,RistrettoPoint),c1: (RistrettoPoint,RistrettoPoint), c_1: (RistrettoPoint,RistrettoPoint),rx: Scalar, ry: Scalar, rm: RistrettoPoint,r_0: Scalar, r_1: Scalar,rand_pk0: (RistrettoPoint,RistrettoPoint),rand_pk1: (RistrettoPoint,RistrettoPoint)) -> bool {
    if b {
        let c00 = rando(pk0,(c0.0+rm,c0.1),r_0);
        let c11 = rando(pk1,(c1.0+rm,c1.1),r_1);
        let c00_rand = (c00.0+(rx*c00.1),c00.1);
        let c11_rand = (c11.0+(ry*c11.1),c11.1);
        let pk0_rand = (pk0.0,pk0.1+(rx*pk0.0));
        let pk1_rand = (pk1.0,pk1.1+(ry*pk1.0));

        c_0 == c00_rand && c_1 == c11_rand && pk0_rand.0 == rand_pk0.0 && pk0_rand.1 == rand_pk0.1 && pk1_rand.0 == rand_pk1.0 && pk1_rand.1 == rand_pk1.1
    }
    else
    {
        (c_0.0 - c_1.0) == (rx*c_0.1) - (ry*c_1.1)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::petpit::{crs_gen,enc};

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
    fn sigpeq_ki_success() {
        assert_eq!(do_key_init_test(true), true);
    }

    #[test]
    fn sigpeq_ki_fail() {
        assert_eq!(do_key_init_test(false), false);
    }

    fn sigpeq_test(should_succeed: bool) -> bool{
        // Generate a key pair
        let (pk0,sk0) = crs_gen();
        let (pk1,sk1) = crs_gen();
        let m0= Scalar::zero() * pk0.0;
        let mut m1 = Scalar::one() * pk0.1;
        if should_succeed {
            m1 = m0
        }

        let c0 = enc(pk0, m0);
        let c1 = enc(pk1, m1);

        let mut bo = true;
        let mut i = 0;
        while i < 128 && bo {

            let (c_0,c_1,rm,r_0,r_1,rk0,rand_pk0,rand_sk0,rk1,rand_pk1,rand_sk1) = sigpeq_flow_1(pk0,sk0,pk1,sk1,c0,c1);

            let b = sigpeq_flow_2();

            let (rx,ry) = sigpeq_flow_3(b,rk0,rk1,rand_sk0,rand_sk1);

            bo = sigpeq_flow_4(b,pk0,pk1,c0,c_0,c1,c_1,rx,ry,rm,r_0,r_1,rand_pk0,rand_pk1);

            i = i+1;
        }
        bo
    }

    #[test]
    fn success() {
        assert_eq!(sigpeq_test(true), true);
    }

    #[test]
    fn fail() {
        assert_eq!(sigpeq_test(false), false);
    }
}