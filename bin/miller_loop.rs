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
    aggregate_proof::{define_recursive_proof, miller_loop_main},
    miller_loop::MillerLoopStark,
    native::{Fp, Fp2},
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type MlStark = MillerLoopStark<F, D>;

fn main_thread() {
    let rng = &mut ark_std::rand::thread_rng();
    let g1 = G1Affine::rand(rng);
    let g2 = G2Affine::rand(rng);

    println!("Starting Miller Loop Proving");

    let s = Instant::now();

    let (stark_ml, proof_ml, config_ml) = miller_loop_main::<F, C, D>(
        Fp::get_fp_from_biguint(g1.x.to_string().parse::<BigUint>().unwrap()),
        Fp::get_fp_from_biguint(g1.y.to_string().parse::<BigUint>().unwrap()),
        Fp2([
            Fp::get_fp_from_biguint(g2.x.c0.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(g2.x.c1.to_string().parse::<BigUint>().unwrap()),
        ]),
        Fp2([
            Fp::get_fp_from_biguint(g2.y.c0.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(g2.y.c1.to_string().parse::<BigUint>().unwrap()),
        ]),
        Fp2([
            Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()),
            Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
        ]),
    );

    println!("Miller Loop Proving Done {:?}", s.elapsed());

    let circuit_config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
    let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(circuit_config);

    let pt = define_recursive_proof::<F, C, MlStark, C, D>(
        stark_ml,
        &proof_ml,
        &config_ml,
        false,
        &mut builder,
    );

    // TODO: should it be zero
    let zero = builder.zero();
    let mut pw = PartialWitness::new();
    starky::recursive_verifier::set_stark_proof_with_pis_target(&mut pw, &pt, &proof_ml, zero);

    let s = Instant::now();
    let data = builder.build::<C>();
    println!(
        "time taken for building plonky2 recursive circuit data {:?}",
        s.elapsed()
    );

    let mut target_bytes: Vec<u8> = Vec::new();

    // TODO: Move to serialize proof target
    // target_bytes.write_target_merkle_cap(&pt.proof.trace_cap);
    // target_bytes.write_bool(pt.proof.permutation_zs_cap.is_some());
    // if let Some(permutation_zs_cap) = &pt.proof.permutation_zs_cap {
    //     target_bytes.write_target_merkle_cap(permutation_zs_cap);
    // }
    // target_bytes.write_target_merkle_cap(&pt.proof.quotient_polys_cap);
    // target_bytes.write_target_ext_vec(&pt.proof.openings.local_values);
    // target_bytes.write_target_ext_vec(&pt.proof.openings.next_values);
    // target_bytes.write_bool(pt.proof.openings.permutation_zs.is_some());
    // if let Some(permutation_zs) = &pt.proof.openings.permutation_zs {
    //     target_bytes.write_target_ext_vec(permutation_zs);
    // }
    // target_bytes.write_target_ext_vec(&pt.proof.openings.quotient_polys);

    // target_bytes.write_target_fri_proof(&pt.proof.opening_proof);

    // target_bytes.write_target_vec(&pt.public_inputs);

    println!("Circuit target bytes length {:?}", target_bytes.len());

    println!("Serializing plonky2 circuit");

    let s = Instant::now();
    let circuit_bytes = data
        .to_bytes(
            &CustomGateSerializer,
            &CustomGeneratorSerializer {
                _phantom: PhantomData::<PoseidonGoldilocksConfig>,
            },
        )
        .unwrap();

    println!("The circuit bytes length is {:?}", circuit_bytes.len());

    fs::write("circuit.plonky2_circuit", &circuit_bytes).unwrap();

    println!("Time taken to serialize plonky2 circuit {:?}", s.elapsed());

    let s = Instant::now();

    let circuit_bytes = fs::read("circuit.plonky2_circuit").unwrap();

    let data = CircuitData::<F, C, D>::from_bytes(
        &circuit_bytes,
        &CustomGateSerializer,
        &CustomGeneratorSerializer {
            _phantom: PhantomData::<PoseidonGoldilocksConfig>,
        },
    )
    .unwrap();

    println!(
        "Time taken to deserialize plonky2 circuit {:?}",
        s.elapsed()
    );

    let s = Instant::now();
    let proof = data.prove(pw).unwrap();
    println!("time taken for plonky2 recursive proof {:?}", s.elapsed());

    // let _ = data.verify(proof);

    fs::write("miller_loop_proof", proof.to_bytes()).unwrap();
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
