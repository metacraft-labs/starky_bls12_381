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
use plonky2_crypto::biguint::{BigUintTarget, CircuitBuilderBiguint};

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
    // let ml1_pt = builder.add_virtual_proof_with_pis(&ml1_rec_proof.2);
    // let ml2_pt = builder.add_virtual_proof_with_pis(&ml2_rec_proof.2);
    // let fin_exp1_pt = builder.add_virtual_proof_with_pis(&fin_exp1_public_inputs);
    // let fin_exp2_pt = builder.add_virtual_proof_with_pis(&fin_exp2_public_inputs);

    let ml1_rec_proof_public_inputs = ml1_rec_proof.0.public_inputs;
    let g1_x_input = &ml1_rec_proof_public_inputs[0..12];
    let g1_y_input = &ml1_rec_proof_public_inputs[12..24];
    let g2_x_input_c0 = &ml1_rec_proof_public_inputs[24..36];
    let g2_x_input_c1 = &ml1_rec_proof_public_inputs[36..48];
    let g2_y_input_c0 = &ml1_rec_proof_public_inputs[48..60];
    let g2_y_input_c1 = &ml1_rec_proof_public_inputs[60..72];

    let g1_x_input = BigUint::new(g1_x_input.iter().map(|x| x.0 as u32).collect());
    let g1_y_input = BigUint::new(g1_y_input.iter().map(|x| x.0 as u32).collect());

    let g2_x_input_c0 = BigUint::new(g2_x_input_c0.iter().map(|x| x.0 as u32).collect());
    let g2_x_input_c1 = BigUint::new(g2_x_input_c1.iter().map(|x| x.0 as u32).collect());
    let g2_y_input_c0 = BigUint::new(g2_y_input_c0.iter().map(|x| x.0 as u32).collect());
    let g2_y_input_c1 = BigUint::new(g2_y_input_c1.iter().map(|x| x.0 as u32).collect());
    let g2_x_bigt = [g2_x_input_c0.clone(), g2_x_input_c1];
    let g2_y_bigt = [g2_y_input_c0, g2_y_input_c1];

    let k = builder.constant_biguint(&g2_x_input_c0);

    println!("g1_x_input is: {:?}", g1_x_input); // 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
    println!("g1_y_input is: {:?}", g1_y_input); // 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
    println!("g2_x_bigt is: {:?}", g2_x_bigt); // 4
    println!("g2_y_bigt is: {:?}", g2_y_bigt); // 3
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
    for _ in 0..100 {
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
    use std::{str::FromStr, time::Instant};

    use num_bigint::BigUint;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use plonky2_crypto::biguint::CircuitBuilderBiguint;

    use crate::{
        fp2_plonky2::Fp2Target,
        g2_plonky2::{g2_add_unequal, PointG2Target},
        miller_loop::MillerLoopStark,
        native::{calc_pairing_precomp, Fp, Fp2},
        signature_verification::verify_all_proofs,
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type MlStark = MillerLoopStark<F, D>;

    use super::verify_miller_loop;
    #[test]
    fn test_g2_point_addition() {
        let circuit_config =
            plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder =
            plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(circuit_config);

        // let ax = Fp2([
        //         Fp::get_fp_from_biguint(BigUint::from_str(
        //             "337725438187709982817188701931175748950561864071211469604211805451542415352866003578718608366094520056481699232210"
        //         ).unwrap()),
        //         Fp::get_fp_from_biguint(BigUint::from_str(
        //             "325784474482020989596135374893471919876505088991873421195308352667079503424389512976821068246925718319548045276021"
        //         ).unwrap()),
        //     ]);
        // let ay = Fp2([
        //         Fp::get_fp_from_biguint(BigUint::from_str(
        //             "2965841325781469856973174148258785715970498867849450741444982165189412687797594966692602501064144340797710797471604"
        //         ).unwrap()),
        //         Fp::get_fp_from_biguint(BigUint::from_str(
        //             "1396501224612541682947972324170488919567615665343008985787728980681572855276817422483173426760119128141672533354119"
        //         ).unwrap()),
        //     ]);
        // let bx = Fp2([
        //         Fp::get_fp_from_biguint(BigUint::from_str(
        //             "3310291183651938419676930134503606039576251708119934019650494815974674760881379622302324811830103490883079904029190"
        //         ).unwrap()),
        //         Fp::get_fp_from_biguint(BigUint::from_str(
        //             "845507222118475144290150023685070019360459684233155402409229752404383900284940551672371362493058110240418657298132"
        //         ).unwrap()),
        //     ]);
        // let by = Fp2([
        //         Fp::get_fp_from_biguint(BigUint::from_str(
        //             "569469686320544423596306308487126199229297307366529623191489815159190893993668979352767262071942316086625514601662"
        //         ).unwrap()),
        //         Fp::get_fp_from_biguint(BigUint::from_str(
        //             "2551756239942517806379811015764241238167383065214268002625836091916337464087928632477808357405422759164808763594986"
        //         ).unwrap()),
        //     ]);

        let N = 12;
        let ax_c0 = builder.add_virtual_biguint_target(N);
        let ax_c1 = builder.add_virtual_biguint_target(N);
        let ay_c0 = builder.add_virtual_biguint_target(N);
        let ay_c1 = builder.add_virtual_biguint_target(N);
        let a = [[ax_c0, ax_c1], [ay_c0, ay_c1]];

        let bx_c0 = builder.add_virtual_biguint_target(N);
        let bx_c1 = builder.add_virtual_biguint_target(N);
        let by_c0 = builder.add_virtual_biguint_target(N);
        let by_c1 = builder.add_virtual_biguint_target(N);
        let b = [[bx_c0, bx_c1], [by_c0, by_c1]];

        let c = g2_add_unequal(&mut builder, &a, &b);
        for _ in 0..10 {}

        let now = Instant::now();
        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let _proof = data.prove(pw);
        println!("time: {:?}", now.elapsed());
    }

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
        let g2_identity_x = Fp2::one() + Fp2::one() + Fp2::one() + Fp2::one(); // 4
        let g2_identity_y = Fp2::one() + Fp2::one() + Fp2::one() + Fp2::one() + Fp2::one(); // 5
        let g2_identity_inf = Fp2::zero();

        let ell_coeffs = calc_pairing_precomp(g2_identity_x, g2_identity_y, g2_identity_inf);
        let ell_coeffs_x_c0 = ell_coeffs[0][0].0[0].to_biguint();
        let ell_coeffs_x_c1 = ell_coeffs[0][0].0[1].to_biguint();
        let ell_coeffs_y_c0 = ell_coeffs[0][1].0[0].to_biguint();
        let ell_coeffs_y_c1 = ell_coeffs[0][1].0[1].to_biguint();
        let ell_coeffs_z_c0 = ell_coeffs[0][2].0[0].to_biguint();
        let ell_coeffs_z_c1 = ell_coeffs[0][2].0[1].to_biguint();
        println!("ell_coeffs.len() is: {:?}", ell_coeffs.len());
        println!("ell_coeffs_x_c0 are: {:?}", ell_coeffs_x_c0);
        println!("ell_coeffs_x_c1 are: {:?}", ell_coeffs_x_c1);
        println!("ell_coeffs_y_c0 are: {:?}", ell_coeffs_y_c0);
        println!("ell_coeffs_y_c1 are: {:?}", ell_coeffs_y_c1);
        println!("ell_coeffs_z_c0 are: {:?}", ell_coeffs_z_c0);
        println!("ell_coeffs_z_c1 are: {:?}", ell_coeffs_z_c1);
        println!("----------------------------------------------------------------");
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
