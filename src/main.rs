use ark_bls12_381::{
    g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::short_weierstrass::Projective;
use ark_ec::AffineRepr;
use ark_ec::{pairing::Pairing, short_weierstrass::Affine, Group};
use ark_std::UniformRand;
use eth_types::{
    eth2::{BeaconBlockHeader, SigningData, SyncAggregate, SyncCommittee, SyncCommitteeUpdate},
    H256,
};
use num_bigint::BigUint;
use plonky2::plonk::{
    circuit_data::CircuitConfig,
    config::{GenericConfig, PoseidonGoldilocksConfig},
};
use serde_json::{self, Value};
use starky_bls12_381::{
    aggregate_proof::{
        aggregate_proof, final_exponentiate_main, miller_loop_main, recursive_proof,
    },
    calc_pairing_precomp::PairingPrecompStark,
    ecc_aggregate::ECCAggStark,
    final_exponentiate::FinalExponentiateStark,
    fp12_mul::FP12MulStark,
    miller_loop::MillerLoopStark,
    native::{calc_pairing_precomp, miller_loop, Fp, Fp12, Fp2},
};
use std::io::BufReader;
use std::{fs::File, str::FromStr};
use tree_hash::TreeHash;

fn main_thread() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    type PpStark = PairingPrecompStark<F, D>;
    type MlStark = MillerLoopStark<F, D>;
    type Fp12MulStark = FP12MulStark<F, D>;
    type FeStark = FinalExponentiateStark<F, D>;
    type ECAggStark = ECCAggStark<F, D>;

    let config = CircuitConfig::standard_recursion_config();
    let rng = &mut ark_std::rand::thread_rng();
    let g1 = G1Affine::generator();
    let r = G1Affine::rand(rng);
    let sk: Fr = Fr::rand(rng);
    let pk = Into::<G1Affine>::into(g1 * sk);
    let message = G2Affine::rand(rng);
    let signature = Into::<G2Affine>::into(message * sk);

    let pk_message = ark_bls12_381::Bls12_381::pairing(pk, message).0;
    let g1_signature = ark_bls12_381::Bls12_381::pairing(G1Affine::generator(), signature).0;

    assert_eq!(pk_message, g1_signature);

    // let result_message = miller_loop(
    //     Fp::get_fp_from_biguint(pk.x.to_string().parse::<BigUint>().unwrap()),
    //     Fp::get_fp_from_biguint(pk.y.to_string().parse::<BigUint>().unwrap()),
    //     Fp2([
    //         Fp::get_fp_from_biguint(message.x.c0.to_string().parse::<BigUint>().unwrap()),
    //         Fp::get_fp_from_biguint(message.x.c1.to_string().parse::<BigUint>().unwrap()),
    //     ]),
    //     Fp2([
    //         Fp::get_fp_from_biguint(message.y.c0.to_string().parse::<BigUint>().unwrap()),
    //         Fp::get_fp_from_biguint(message.y.c1.to_string().parse::<BigUint>().unwrap()),
    //     ]),
    //     Fp2([
    //         Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()),
    //         Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
    //     ]),
    // );

    // let result_signature = miller_loop(
    //     Fp::get_fp_from_biguint(g1.x.to_string().parse::<BigUint>().unwrap()),
    //     Fp::get_fp_from_biguint(g1.y.to_string().parse::<BigUint>().unwrap()),
    //     Fp2([
    //         Fp::get_fp_from_biguint(signature.x.c0.to_string().parse::<BigUint>().unwrap()),
    //         Fp::get_fp_from_biguint(signature.x.c1.to_string().parse::<BigUint>().unwrap()),
    //     ]),
    //     Fp2([
    //         Fp::get_fp_from_biguint(signature.y.c0.to_string().parse::<BigUint>().unwrap()),
    //         Fp::get_fp_from_biguint(signature.y.c1.to_string().parse::<BigUint>().unwrap()),
    //     ]),
    //     Fp2([
    //         Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()),
    //         Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
    //     ]),
    // );

    // let pk_message_native = result_message.final_exponentiate();
    // let g1_signature_native = result_signature.final_exponentiate();

    // assert_eq!(pk_message_native, g1_signature_native);

    // println!("Starting the circuits now");

    // let (stark_ml1, proof_ml1, config_ml1) = miller_loop_main::<F, C, D>(
    //     Fp::get_fp_from_biguint(pk.x.to_string().parse::<BigUint>().unwrap()),
    //     Fp::get_fp_from_biguint(pk.y.to_string().parse::<BigUint>().unwrap()),
    //     Fp2([
    //         Fp::get_fp_from_biguint(message.x.c0.to_string().parse::<BigUint>().unwrap()),
    //         Fp::get_fp_from_biguint(message.x.c1.to_string().parse::<BigUint>().unwrap()),
    //     ]),
    //     Fp2([
    //         Fp::get_fp_from_biguint(message.y.c0.to_string().parse::<BigUint>().unwrap()),
    //         Fp::get_fp_from_biguint(message.y.c1.to_string().parse::<BigUint>().unwrap()),
    //     ]),
    //     Fp2([
    //         Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()),
    //         Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
    //     ]),
    // );
    // let recursive_ml1 =
    //     recursive_proof::<F, C, MlStark, C, D>(stark_ml1, proof_ml1.clone(), &config_ml1, true);

    // println!("{:?}", recursive_ml1.0.public_inputs);

    // println!("second miller loop");
    // let (stark_ml2, proof_ml2, config_ml2) = miller_loop_main::<F, C, D>(
    //     Fp::get_fp_from_biguint(g1.x.to_string().parse::<BigUint>().unwrap()),
    //     Fp::get_fp_from_biguint(g1.y.to_string().parse::<BigUint>().unwrap()),
    //     Fp2([
    //         Fp::get_fp_from_biguint(signature.x.c0.to_string().parse::<BigUint>().unwrap()),
    //         Fp::get_fp_from_biguint(signature.x.c1.to_string().parse::<BigUint>().unwrap()),
    //     ]),
    //     Fp2([
    //         Fp::get_fp_from_biguint(signature.y.c0.to_string().parse::<BigUint>().unwrap()),
    //         Fp::get_fp_from_biguint(signature.y.c1.to_string().parse::<BigUint>().unwrap()),
    //     ]),
    //     Fp2([
    //         Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()),
    //         Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
    //     ]),
    // );
    // let recursive_ml2 =
    //     recursive_proof::<F, C, MlStark, C, D>(stark_ml2, proof_ml2.clone(), &config_ml2, true);

    // let (stark_final_exp, proof_final_exp, config_final_exp) =
    //     final_exponentiate_main::<F, C, D>(result_message);
    // let message_exp = recursive_proof::<F, C, FeStark, C, D>(
    //     stark_final_exp,
    //     proof_final_exp,
    //     &config_final_exp,
    //     true,
    // );

    // let (stark_final_exp, proof_final_exp, config_final_exp) =
    //     final_exponentiate_main::<F, C, D>(result_signature);
    // let signiture_exp = recursive_proof::<F, C, FeStark, C, D>(
    //     stark_final_exp,
    //     proof_final_exp,
    //     &config_final_exp,
    //     true,
    // );
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
