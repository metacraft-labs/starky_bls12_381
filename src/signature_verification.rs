use num_bigint::BigUint;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CommonCircuitData,
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use plonky2_crypto::biguint::BigUintTarget;

use crate::{
    aggregate_proof::{final_exponentiate_main, miller_loop_main, recursive_proof, ProofTuple},
    final_exponentiate::FinalExponentiateStark,
    fp2_plonky2::Fp2Target,
    g1_plonky2::PointG1Target,
    g2_plonky2::{g2_add_unequal, g2_scalar_mul, PointG2Target},
    hash_to_curve::hash_to_curve,
    miller_loop::MillerLoopStark,
    native::{miller_loop, Fp, Fp12, Fp2},
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

type MlStark = MillerLoopStark<F, D>;
type FeStark = FinalExponentiateStark<F, D>;

pub fn calculate_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg: &[Target],
    secret_key: &Fp2Target,
) -> PointG2Target {
    let hm_as_g2_point = hash_to_curve(builder, msg);
    let signature = g2_scalar_mul(builder, &hm_as_g2_point, secret_key);

    signature
}

pub fn verify_miller_loop(x: Fp, y: Fp, q_x: Fp2, q_y: Fp2, q_z: Fp2) -> ProofTuple<F, C, D> {
    let (stark_ml, proof_ml, config_ml) = miller_loop_main::<F, C, D>(x, y, q_x, q_y, q_z);
    let recursive_ml = recursive_proof::<F, C, MlStark, C, D>(stark_ml, proof_ml, &config_ml, true);

    recursive_ml
}
pub fn verify_final_exponentiation(f: Fp12) -> (Fp12, CommonCircuitData<F, D>) {
    let (stark_final_exp, proof_final_exp, config_final_exp) =
        final_exponentiate_main::<F, C, D>(f);
    let recursive_final_exp = recursive_proof::<F, C, FeStark, C, D>(
        stark_final_exp,
        proof_final_exp,
        &config_final_exp,
        true,
    );

    let final_exp_circuit_proof_data = recursive_final_exp.2;

    (f, final_exp_circuit_proof_data)
}

pub fn verify_all_proofs(
    builder: &mut CircuitBuilder<F, D>,
    ml1_rec_proof: ProofTuple<F, C, D>,
    // ml2_rec_proof: ProofTuple<F, C, D>,
    // fin_exp1_public_inputs: CommonCircuitData<F, D>,
    // fin_exp2_public_inputs: CommonCircuitData<F, D>,
    // g1_generator: &PointG1Target,
    // signature: &PointG2Target,
    // public_key: &PointG1Target,
    // hm_g2: &PointG2Target,
) {
    let ml1_pt = builder.add_virtual_proof_with_pis(&ml1_rec_proof.2);
    // let ml2_pt = builder.add_virtual_proof_with_pis(&ml2_rec_proof.2);
    // let fin_exp1_pt = builder.add_virtual_proof_with_pis(&fin_exp1_public_inputs);
    // let fin_exp2_pt = builder.add_virtual_proof_with_pis(&fin_exp2_public_inputs);

    let ml1_rec_proof_public_inputs = ml1_rec_proof.0.public_inputs;
    let g1_x_input = &ml1_rec_proof_public_inputs[0..12];
    let g1_y_input = &ml1_rec_proof_public_inputs[12..24];
    let g2_x_input = &ml1_rec_proof_public_inputs[24..48];
    let g2_y_input = &ml1_rec_proof_public_inputs[48..72];
    let g2_z_input = &ml1_rec_proof_public_inputs[72..96];

    let test_g2_x_input_1 = &ml1_rec_proof_public_inputs[24..36];
    let test_g2_x_input_2 = &ml1_rec_proof_public_inputs[36..48];
    let test_g2_x_input_1 = BigUint::new(test_g2_x_input_1.iter().map(|x| x.0 as u32).collect());
    let test_g2_x_input_2 = BigUint::new(test_g2_x_input_2.iter().map(|x| x.0 as u32).collect());

    let test_g2_y_input_1 = &ml1_rec_proof_public_inputs[24..36];
    let test_g2_y_input_2 = &ml1_rec_proof_public_inputs[36..48];
    let test_g2_y_input_1 = BigUint::new(test_g2_y_input_1.iter().map(|x| x.0 as u32).collect());
    let test_g2_y_input_2 = BigUint::new(test_g2_y_input_2.iter().map(|x| x.0 as u32).collect());

    let test_g2_z_input_1 = &ml1_rec_proof_public_inputs[72..84];
    let test_g2_z_input_2 = &ml1_rec_proof_public_inputs[84..96];
    let test_g2_z_input_1 = BigUint::new(test_g2_z_input_1.iter().map(|x| x.0 as u32).collect());
    let test_g2_z_input_2 = BigUint::new(test_g2_z_input_2.iter().map(|x| x.0 as u32).collect());

    println!("test_g2_x_input_1 is: {:?}", test_g2_x_input_1); // 0
    println!("test_g2_x_input_2 is: {:?}", test_g2_x_input_2); // 0
    let test_g2_x_input = [test_g2_x_input_1 - 1u32, test_g2_x_input_2 - 1u32];
    println!("test_g2_x_input_2 is: {:?}", test_g2_x_input); // 0

    println!("test_g2_y_input_1 is: {:?}", test_g2_y_input_1); // 0
    println!("test_g2_y_input_2 is: {:?}", test_g2_y_input_2); // 0
    let test_g2_y_input = [test_g2_y_input_1 + 1u32, test_g2_y_input_2 + 1u32];
    println!("test_g2_y_input is: {:?}", test_g2_y_input); // 0

    println!("test_g2_z_input_1 is: {:?}", test_g2_z_input_1); // 1
    println!("test_g2_z_input_2 is: {:?}", test_g2_z_input_2); // 1
    let test_g2_z_input = [test_g2_z_input_1 + 1u32, test_g2_z_input_2 + 1u32];
    println!("test_g2_z_input is: {:?}", test_g2_z_input); // 1

    println!("==================================================================");

    let g1_x_input = BigUint::new(g1_x_input.iter().map(|x| x.0 as u32).collect());
    let g1_y_input = BigUint::new(g1_y_input.iter().map(|x| x.0 as u32).collect());
    let g2_x_input = BigUint::new(g2_x_input.iter().map(|x| x.0 as u32).collect());
    let g2_y_input = BigUint::new(g2_y_input.iter().map(|x| x.0 as u32).collect());
    let g2_z_input = BigUint::new(g2_z_input.iter().map(|x| x.0 as u32).collect());

    println!("g1_x_input is: {:?}", g1_x_input); // 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
    println!("g1_y_input is: {:?}", g1_y_input); // 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
    println!("g2_x_input is: {:?}", g2_x_input); // 0
    println!("g2_y_input is: {:?}", g2_y_input); // 0
    println!("g2_z_input is: {:?}", g2_z_input); // 1

    // for i in 0..ml1_pt.public_inputs.len() {
    //     builder.connect(ml1_pt.public_inputs[i], ml2_pt.public_inputs[i]);
    // }

    // for i in 0..fin_exp1_pt.public_inputs.len() {
    //     builder.connect(fin_exp1_pt.public_inputs[i], fin_exp2_pt.public_inputs[i]);
    // }
}

pub fn signature_verification<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    _builder: &mut CircuitBuilder<F, D>,
    _msg: &[Target],
    _signature: &PointG2Target,
    _public_key: &PointG1Target,
) {
}

pub fn signature_aggregation(
    builder: &mut CircuitBuilder<F, D>,
    g2_point: PointG2Target,
) -> PointG2Target {
    let mut point_addition = g2_point.clone();
    for i in 0..100 {
        point_addition = g2_add_unequal(builder, &point_addition, &g2_point);
    }
    point_addition
}

pub fn benchmark_curve_point_addition<F: RichField + Extendable<D>, const D: usize>(
    _builder: &mut CircuitBuilder<F, D>,
) {
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use num_bigint::BigUint;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::{
        miller_loop::MillerLoopStark,
        native::{Fp, Fp2},
        signature_verification::verify_all_proofs,
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type MlStark = MillerLoopStark<F, D>;

    use super::verify_miller_loop;

    #[test]
    fn test_verify_miller_loop() {
        let circuit_config =
            plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder =
            plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(circuit_config);
        let g1_generator_x: BigUint = BigUint::from_str("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507").unwrap();
        let g1_generator_y: BigUint = BigUint::from_str("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569").unwrap();
        let g1_generator_x = Fp::get_fp_from_biguint(g1_generator_x);
        let g1_generator_y = Fp::get_fp_from_biguint(g1_generator_y);
        let g2_generator_x_c0: BigUint = BigUint::from_str("352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160").unwrap();
        let g2_generator_x_c0 = Fp::get_fp_from_biguint(g2_generator_x_c0);

        let g2_generator_x_c1: BigUint = BigUint::from_str("3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758").unwrap();
        let g2_generator_x_c1 = Fp::get_fp_from_biguint(g2_generator_x_c1);

        let g2_generator_y_c0: BigUint = BigUint::from_str("1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905").unwrap();
        let g2_generator_y_c0 = Fp::get_fp_from_biguint(g2_generator_y_c0);

        let g2_generator_y_c1: BigUint = BigUint::from_str("927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582").unwrap();
        let g2_generator_y_c1 = Fp::get_fp_from_biguint(g2_generator_y_c1);

        let mut g2_identity_x = Fp2::zero();
        g2_identity_x.0[0] = g2_generator_x_c0;
        g2_identity_x.0[1] = g2_generator_x_c1;
        let mut g2_identity_y = Fp2::zero();
        g2_identity_y.0[0] = g2_generator_y_c0;
        g2_identity_y.0[1] = g2_generator_y_c1;
        let g2_identity_inf = Fp2::zero();
        let x = verify_miller_loop(
            g1_generator_x,
            g1_generator_y,
            g2_identity_x,
            g2_identity_y,
            g2_identity_inf,
        );

        verify_all_proofs(&mut builder, x);

        assert!(false)
    }
}
