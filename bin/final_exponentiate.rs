use std::{fs, marker::PhantomData, str::FromStr, time::Instant};

use ark_bls12_381::{G1Affine, G1Projective, G2Affine};
use ark_ec::Group;
use ark_std::UniformRand;
use num_bigint::BigUint;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::CircuitData,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
    util::serialization::{Buffer, IoResult, Read, Write},
};
use plonky2_circuit_serializer::serializer::{CustomGateSerializer, CustomGeneratorSerializer};
use starky_bls12_381::{
    aggregate_proof::{define_recursive_proof, final_exponentiate_main, miller_loop_main},
    miller_loop::MillerLoopStark,
    native::{Fp, Fp12, Fp2}, final_exponentiate::FinalExponentiateStark,
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type FeStark = FinalExponentiateStark<F, D>;

// TODO: We should have miller loop server which will receive G1 and G2 elements and return proof for them
// As the circuit is big and it is best if we have it loaded in memory
fn main_thread() {
    let rng = &mut ark_std::rand::thread_rng();

    let fq = ark_bls12_381::Fq12::rand(rng);

    let fp12 = Fp12([
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

    println!("Final exponetiate stark proof started");

    let s = Instant::now();

    let (stark_final_exp, proof_final_exp, config_final_exp) =
        final_exponentiate_main::<F, C, D>(fp12);

    println!("Final exponetiate stark proof done in {:?}", s.elapsed());

    let circuit_config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
    let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(circuit_config);

    let pt = define_recursive_proof::<F, C, FeStark, C, D>(
        stark_final_exp,
        &proof_final_exp,
        &config_final_exp,
        false,
        &mut builder,
    );

    // TODO: should it be zero
    let zero = builder.zero();
    let mut pw = PartialWitness::new();
    starky::recursive_verifier::set_stark_proof_with_pis_target(
        &mut pw,
        &pt,
        &proof_final_exp,
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

    fs::write("final_exponentiate_proof", proof.to_bytes()).unwrap();
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
