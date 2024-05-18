use std::fs;

use num_bigint::BigUint;
use plonky2::{
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
    util::serialization::GateSerializer,
};
use plonky2_circuit_serializer::serializer::CustomGateSerializer;
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint},
    u32::arithmetic_u32::U32Target,
};
use starky_bls12_381::fp12_mul;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn main() {
    let common_circuit_data = CommonCircuitData::<F, D>::from_bytes(
        fs::read("common_circuit_data").unwrap(),
        &CustomGateSerializer,
    )
    .unwrap();

    let first_miller_loop = ProofWithPublicInputs::<F, C, D>::from_bytes(
        fs::read("first_miller_loop_proof").unwrap(),
        &common_circuit_data,
    )
    .unwrap();

    let second_miller_loop = ProofWithPublicInputs::<F, C, D>::from_bytes(
        fs::read("second_miller_loop_proof").unwrap(),
        &common_circuit_data,
    )
    .unwrap();

    let fp12_mul_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
        fs::read("fp12_mul_proof").unwrap(),
        &common_circuit_data,
    )
    .unwrap();

    let final_exponentiate_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
        fs::read("final_exponentiate_proof").unwrap(),
        &common_circuit_data,
    )
    .unwrap();

    let first_ml_pub_inputs = first_miller_loop.public_inputs;
    let second_ml_pub_inputs = second_miller_loop.public_inputs;

    let circuit_config = CircuitConfig::standard_recursion_config();

    let mut builder = CircuitBuilder::<F, D>::new(circuit_config);

    let g1_x_input = builder.constant_biguint(&BigUint::new(
        first_ml_pub_inputs[0..12]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));

    let g1_y_input = builder.constant_biguint(&BigUint::new(
        first_ml_pub_inputs[12..24]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));

    let g2_x_input_c0 = builder.constant_biguint(&BigUint::new(
        first_ml_pub_inputs[24..36]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));
    let g2_x_input_c1 = builder.constant_biguint(&BigUint::new(
        first_ml_pub_inputs[36..48]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));
    let g2_y_input_c0 = builder.constant_biguint(&BigUint::new(
        first_ml_pub_inputs[48..60]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));
    let g2_y_input_c1 = builder.constant_biguint(&BigUint::new(
        first_ml_pub_inputs[60..72]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));

    // TODO: this should be the real generator point
    let g1_generator = [
        builder.constant_biguint(&BigUint::new(vec![1u32])),
        builder.constant_biguint(&BigUint::new(vec![1u32])),
    ];

    builder.connect_biguint(&g1_generator[0], &g1_x_input);
    builder.connect_biguint(&g1_generator[1], &g1_y_input);

    builder.connect_biguint(&signature[0][0], &g2_x_input_c0);
    builder.connect_biguint(&signature[0][1], &g2_x_input_c1);
    builder.connect_biguint(&signature[1][0], &g2_y_input_c0);
    builder.connect_biguint(&signature[1][1], &g2_y_input_c1);
}
