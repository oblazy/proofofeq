#[macro_use]
extern crate bencher;

use bencher::Bencher;

use curve25519_dalek::scalar::Scalar;

use petpit::*;
//use petpiteq::*;

use rand_os::OsRng;

pub fn doprot() -> bool {
    let (pk,sk) = crs_gen();
    let m0 = Scalar::zero() * pk.0;
    let m1 = Scalar::one() * pk.1;

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

fn do_fast_prot() -> bool{
    // Generate a key pair
    let (pk,sk) = crs_gen();
    let m0 = Scalar::zero() * pk.0;
    let m1 = Scalar::one() * pk.1;

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

fn eq_do_fast_prot() -> bool{
    // Generate a key pair
    let (pk,sk) = crs_gen();
    let m0 = Scalar::zero() * pk.0;
    let m1 = m0;

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

fn eq_do_slow_prot() -> bool{
    // Generate a key pair
    let (pk,sk) = crs_gen();
    let m0 = Scalar::zero() * pk.0;
    let m1 = m0;

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

        bo=eq_flow_5s(cz,sa,rm);
        i = i+1;
    }
    bo
}

fn rspeq_do_prot() -> bool{
    // Generate a key pair
    let (pk0,_) = crs_gen();
    let (pk1,_) = crs_gen();
    let m0 = Scalar::zero() * pk0.0;
    let m1 = m0;

    let mut rng = OsRng::new().unwrap();
    let r0 = Scalar::random(&mut rng);
    let r1 = Scalar::random(&mut rng);

    let c0 = rspeq_enc(pk0,m0,r0);
    let c1 = rspeq_enc(pk1,m1,r1);

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

fn sigpeq_do_prot() -> bool{
    // Generate a key pair
    let (pk0,sk0) = crs_gen();
    let (pk1,sk1) = crs_gen();
    let m0 = Scalar::zero() * pk0.0;
    let m1 = m0;

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

fn slow(bench: &mut Bencher) {
    bench.iter(|| {
        doprot();
    });
}

fn fast(bench: &mut Bencher) {
    bench.iter(|| {
        do_fast_prot();
    });
}

fn fast_eq(bench: &mut Bencher) {
    bench.iter(|| {
        eq_do_fast_prot();
    });
}

fn slow_eq(bench: &mut Bencher) {
    bench.iter(|| {
        eq_do_slow_prot();
    });
}

fn rspeq(bench: &mut Bencher) {
    bench.iter(|| {
        rspeq_do_prot();
    });
}

fn sigpeq(bench: &mut Bencher) {
    bench.iter(|| {
        sigpeq_do_prot();
    });
}

benchmark_group!(benches, slow,fast,fast_eq,slow_eq,rspeq,sigpeq);
benchmark_main!(benches);
