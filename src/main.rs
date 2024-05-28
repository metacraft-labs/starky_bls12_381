use ark_bls12_381::{
    g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
    Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{pairing::Pairing, short_weierstrass::Affine, Group};
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
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
use snowbridge_milagro_bls::BLSCurve::{big::Big, bls381::utils::hash_to_curve_g2, ecp2::ECP2};
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
use std::{fs::File, ops::Neg, str::FromStr};
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
    let pubkey = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    let signature = "a42ae16f1c2a5fa69c04cb5998d2add790764ce8dd45bf25b29b4700829232052b52352dcff1cf255b3a7810ad7269601810f03b2bc8b68cf289cf295b206770605a190b6842583e47c3d1c0f73c54907bfb2a602157d46a4353a20283018763";
    let msg = "1212121212121212121212121212121212121212121212121212121212121212";

    let g1 = G1Projective::generator();
    let pubkey_g1 =
        G1Affine::deserialize_compressed_unchecked(&*hex::decode(pubkey).unwrap()).unwrap();
    let signature_g2 =
        G2Affine::deserialize_compressed_unchecked(&*hex::decode(signature).unwrap()).unwrap();
    let message_g2 = hash_to_curve_g2(
        &hex::decode(msg).unwrap(),
        "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes(),
    );
    
    let message_g2 = convert_ecp2_to_g2affine(message_g2);

    let neg_g1 = g1.neg();

    let result_message = miller_loop(
        Fp::get_fp_from_biguint(pubkey_g1.x.to_string().parse::<BigUint>().unwrap()),
        Fp::get_fp_from_biguint(pubkey_g1.y.to_string().parse::<BigUint>().unwrap()),
        Fp2([
            Fp::get_fp_from_biguint(message_g2.x.c0.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(message_g2.x.c1.to_string().parse::<BigUint>().unwrap()),
        ]),
        Fp2([
            Fp::get_fp_from_biguint(message_g2.y.c0.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(message_g2.y.c1.to_string().parse::<BigUint>().unwrap()),
        ]),
        Fp2([
            Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()),
            Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
        ]),
    );

    let result_signature = miller_loop(
        Fp::get_fp_from_biguint(neg_g1.x.to_string().parse::<BigUint>().unwrap()),
        Fp::get_fp_from_biguint(neg_g1.y.to_string().parse::<BigUint>().unwrap()),
        Fp2([
            Fp::get_fp_from_biguint(signature_g2.x.c0.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(signature_g2.x.c1.to_string().parse::<BigUint>().unwrap()),
        ]),
        Fp2([
            Fp::get_fp_from_biguint(signature_g2.y.c0.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(signature_g2.y.c1.to_string().parse::<BigUint>().unwrap()),
        ]),
        Fp2([
            Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()),
            Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
        ]),
    );
    let fp12_mul = result_message * result_signature;

    let final_exp = fp12_mul.final_exponentiate();

    println!("fp12_mul: {:?}", fp12_mul);
    println!("final_exp: {:?}", final_exp);

    let (stark_final_exp, proof_final_exp, config_final_exp) =
        final_exponentiate_main::<F, C, D>(fp12_mul);
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

fn convert_ecp2_to_g2affine(ecp2_point: ECP2) -> G2Affine {
    let x = Fq2::new(
        convert_big_to_fq(ecp2_point.getpx().geta()),
        convert_big_to_fq(ecp2_point.getpx().getb()),
    );

    let y = Fq2::new(
        convert_big_to_fq(ecp2_point.getpy().geta()),
        convert_big_to_fq(ecp2_point.getpy().getb()),
    );

    G2Affine::new(x, y)
}

fn convert_big_to_fq(big: Big) -> Fq {
    let bytes = &hex::decode(big.to_string()).unwrap();
    Fq::from_be_bytes_mod_order(bytes)
}
