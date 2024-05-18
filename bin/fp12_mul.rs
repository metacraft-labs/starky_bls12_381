use std::{fs, time::Instant};

use ark_std::UniformRand;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
};
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint},
    u32::arithmetic_u32::U32Target,
};
use starky_bls12_381::{
    aggregate_proof::{define_recursive_proof, fp12_mul_main},
    fp12_mul::FP12MulStark,
    native::{Fp, Fp12},
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

type Fp12MulStark = FP12MulStark<F, D>;

fn main_thread() {
    let rng = &mut ark_std::rand::thread_rng();

    let fq = ark_bls12_381::Fq12::rand(rng);

    let fp12_1 = Fp12([
        Fp::get_fp_from_biguint(fq.c0.c0.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c0.c0.c1.0.into()),
        Fp::get_fp_from_biguint(fq.c0.c1.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c0.c1.c1.0.into()),
        Fp::get_fp_from_biguint(fq.c0.c2.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c0.c2.c1.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c0.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c0.c1.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c1.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c1.c1.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c2.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c2.c1.0.into()),
    ]);

    let fq = ark_bls12_381::Fq12::rand(rng);

    let fp12_2 = Fp12([
        Fp::get_fp_from_biguint(fq.c0.c0.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c0.c0.c1.0.into()),
        Fp::get_fp_from_biguint(fq.c0.c1.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c0.c1.c1.0.into()),
        Fp::get_fp_from_biguint(fq.c0.c2.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c0.c2.c1.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c0.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c0.c1.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c1.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c1.c1.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c2.c0.0.into()),
        Fp::get_fp_from_biguint(fq.c1.c2.c1.0.into()),
    ]);

    let s = Instant::now();
    println!("Starting FP12 Mul Proving");
    let (stark_fp12_mul, proof_fp12_mul, config_fp12_mul) =
        fp12_mul_main::<F, C, D>(fp12_1, fp12_2);
    println!("FP12 Mul Proving Done {:?}", s.elapsed());

    let circuit_config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
    let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(circuit_config);

    let pt = define_recursive_proof::<F, C, Fp12MulStark, C, D>(
        stark_fp12_mul,
        &proof_fp12_mul,
        &config_fp12_mul,
        false,
        &mut builder,
    );

    // TODO: should it be zero
    let zero = builder.zero();
    let mut pw = PartialWitness::new();
    starky::recursive_verifier::set_stark_proof_with_pis_target(
        &mut pw,
        &pt,
        &proof_fp12_mul,
        zero,
    );

    let s = Instant::now();
    let data = builder.build::<C>();
    println!(
        "time taken for building plonky2 recursive circuit data {:?}",
        s.elapsed()
    );

    let s = Instant::now();
    let proof = data.prove(pw).unwrap();
    println!("time taken for plonky2 recursive proof {:?}", s.elapsed());

    let _ = data.verify(proof.clone());

    fs::write("fp12_mul_proof", proof.to_bytes()).unwrap();
}

fn main() {
    std::thread::Builder::new()
        .spawn(|| {
            main_thread();
        })
        .unwrap()
        .join()
        .unwrap();
}
