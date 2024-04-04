use std::str::FromStr;

use ark_bls12_381::G2Affine;
use num_bigint::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, PoseidonGoldilocksConfig},
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
    native::{calc_pairing_precomp, Fp, Fp12, Fp2},
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

pub fn verify_final_exponentiation(f: Fp12) -> ProofTuple<F, C, D> {
    let (stark_final_exp, proof_final_exp, config_final_exp) =
        final_exponentiate_main::<F, C, D>(f);
    let recursive_final_exp = recursive_proof::<F, C, FeStark, C, D>(
        stark_final_exp,
        proof_final_exp,
        &config_final_exp,
        true,
    );

    recursive_final_exp
}

fn fp12_as_biguint_target(
    builder: &mut CircuitBuilder<F, D>,
    f_inputs: Vec<F>,
    i: usize,
) -> Vec<BigUintTarget> {
    let mut f = Vec::new();
    let mut i = i;
    for _ in 0..12 {
        f.push(builder.constant_biguint(&BigUint::new(
            f_inputs[i..i + 12].iter().map(|x| x.0 as u32).collect(),
        )));
        i += 12;
    }

    f
}

fn fp12_as_fp_limbs(f_inputs: Vec<F>, i: usize) -> Vec<Fp> {
    let mut f = Vec::new();
    let mut i = i;
    for _ in 0..12 {
        f.push(Fp::get_fp_from_biguint(BigUint::new(
            f_inputs[i..i + 12].iter().map(|x| x.0 as u32).collect(),
        )));
        i += 12;
    }

    f
}

fn vec_limbs_to_fixed_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

pub fn calculate_ell_coeffs(
    builder: &mut CircuitBuilder<F, D>,
    signature: G2Affine,
) -> PointG2Target {
    let ell_coeffs = calc_pairing_precomp(
        Fp2([
            Fp::get_fp_from_biguint(signature.x.c0.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(signature.x.c1.to_string().parse::<BigUint>().unwrap()),
        ]),
        Fp2([
            Fp::get_fp_from_biguint(signature.y.c0.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(signature.y.c1.to_string().parse::<BigUint>().unwrap()),
        ]),
        Fp2([
            Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()),
            Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
        ]),
    );

    [
        [
            builder.constant_biguint(&ell_coeffs[0][0].0[0].to_biguint()),
            builder.constant_biguint(&ell_coeffs[0][0].0[1].to_biguint()),
        ],
        [
            builder.constant_biguint(&ell_coeffs[0][1].0[0].to_biguint()),
            builder.constant_biguint(&ell_coeffs[0][1].0[1].to_biguint()),
        ],
    ]
}

pub fn test_fml_output(
    builder: &mut CircuitBuilder<F, D>,
    first_ml_proof: ProofTuple<F, C, D>,
    g1_generator: &PointG1Target,
    signature: &PointG2Target,
) {
    let first_ml_pub_inputs = first_ml_proof.0.public_inputs;

    // FIRST MILLER LOOP
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

    builder.connect_biguint(&g1_generator[0], &g1_x_input);
    builder.connect_biguint(&g1_generator[1], &g1_y_input);

    builder.connect_biguint(&signature[0][0], &g2_x_input_c0);
    builder.connect_biguint(&signature[0][1], &g2_x_input_c1);
    builder.connect_biguint(&signature[1][0], &g2_y_input_c0);
    builder.connect_biguint(&signature[1][1], &g2_y_input_c1);

    // first miller loop Fp12 is 72 -> 72 + 144
    // Fp12 - [Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp]
    let first_ml_r = fp12_as_fp_limbs(first_ml_pub_inputs, 96);
    // let (_, proof_final_exp, _) = final_exponentiate_main::<F, C, D>(Fp12(
    //     vec_limbs_to_fixed_array::<Fp, 12>(first_ml_r.clone()),
    // ));
    println!("///////////////////////////////////////////////////////////////////////////");
    println!(
        "first_ml_r: {:?}",
        Fp12(vec_limbs_to_fixed_array::<Fp, 12>(first_ml_r.clone()))
    );

    println!(
        "first_ml_r: {:?}",
        Fp12(vec_limbs_to_fixed_array::<Fp, 12>(first_ml_r)).get_u32_slice()
    );
    // let first_fin_exp_pub_inputs = proof_final_exp.public_inputs;
    // let first_fin_exp_pub_inputs = fp12_as_biguint_target(builder, first_fin_exp_pub_inputs, 0);
}

pub fn verify_all_proofs(
    builder: &mut CircuitBuilder<F, D>,
    first_ml_proof: ProofTuple<F, C, D>,
    second_ml_proof: ProofTuple<F, C, D>,
    g1_generator: &PointG1Target,
    signature: &PointG2Target,
    public_key: &PointG1Target,
    hm_g2: &PointG2Target,
) {
    let first_ml_pub_inputs = first_ml_proof.0.public_inputs;
    let second_ml_pub_inputs = second_ml_proof.0.public_inputs;

    // FIRST MILLER LOOP
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

    builder.connect_biguint(&g1_generator[0], &g1_x_input);
    builder.connect_biguint(&g1_generator[1], &g1_y_input);

    builder.connect_biguint(&signature[0][0], &g2_x_input_c0);
    builder.connect_biguint(&signature[0][1], &g2_x_input_c1);
    builder.connect_biguint(&signature[1][0], &g2_y_input_c0);
    builder.connect_biguint(&signature[1][1], &g2_y_input_c1);

    // first miller loop Fp12 is 72 -> 72 + 144
    // Fp12 - [Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp]
    let first_ml_r = fp12_as_fp_limbs(first_ml_pub_inputs, 72);
    let (_, proof_final_exp, _) =
        final_exponentiate_main::<F, C, D>(Fp12(vec_limbs_to_fixed_array::<Fp, 12>(first_ml_r)));
    let first_fin_exp_pub_inputs = proof_final_exp.public_inputs;
    let first_fin_exp_pub_inputs = fp12_as_biguint_target(builder, first_fin_exp_pub_inputs, 0);

    // SECOND MILLER LOOP
    let g1_x_input = builder.constant_biguint(&BigUint::new(
        second_ml_pub_inputs[0..12]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));
    let g1_y_input = builder.constant_biguint(&BigUint::new(
        second_ml_pub_inputs[12..24]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));

    let g2_x_input_c0 = builder.constant_biguint(&BigUint::new(
        second_ml_pub_inputs[24..36]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));
    let g2_x_input_c1 = builder.constant_biguint(&BigUint::new(
        second_ml_pub_inputs[36..48]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));
    let g2_y_input_c0 = builder.constant_biguint(&BigUint::new(
        second_ml_pub_inputs[48..60]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));
    let g2_y_input_c1 = builder.constant_biguint(&BigUint::new(
        second_ml_pub_inputs[60..72]
            .iter()
            .map(|x| x.0 as u32)
            .collect(),
    ));

    builder.connect_biguint(&public_key[0], &g1_x_input);
    builder.connect_biguint(&public_key[1], &g1_y_input);

    builder.connect_biguint(&hm_g2[0][0], &g2_x_input_c0);
    builder.connect_biguint(&hm_g2[0][1], &g2_x_input_c1);
    builder.connect_biguint(&hm_g2[1][0], &g2_y_input_c0);
    builder.connect_biguint(&hm_g2[1][1], &g2_y_input_c1);

    // second miller loop Fp12 is 72 -> 72 + 144
    // Fp12 - [Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp,Fp]
    let second_ml_r = fp12_as_fp_limbs(second_ml_pub_inputs.clone(), 96);

    let (_, proof_final_exp, _) =
        final_exponentiate_main::<F, C, D>(Fp12(vec_limbs_to_fixed_array::<Fp, 12>(second_ml_r)));
    let second_fin_exp_pub_inputs = proof_final_exp.public_inputs;
    let second_fin_exp_pub_inputs = fp12_as_biguint_target(builder, second_fin_exp_pub_inputs, 0);

    for i in 0..12 {
        builder.connect_biguint(&first_fin_exp_pub_inputs[i], &second_fin_exp_pub_inputs[i]);
    }
}

// FAILS
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

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Instant};

    use ark_bls12_381::{Fr, G1Affine, G2Affine};
    use ark_ec::AffineRepr;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
    };
    use plonky2_crypto::biguint::CircuitBuilderBiguint;

    use crate::{
        fp_plonky2::N,
        g1_plonky2::PointG1Target,
        g2_plonky2::{g2_add_unequal, PointG2Target},
        miller_loop::MillerLoopStark,
        native::{miller_loop, Fp, Fp2},
        signature_verification::{calculate_ell_coeffs, verify_all_proofs},
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type _MlStark = MillerLoopStark<F, D>;

    use super::{test_fml_output, verify_miller_loop};
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

        let _c = g2_add_unequal(&mut builder, &a, &b);
        for _ in 0..10 {}

        let now = Instant::now();
        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let _proof = data.prove(pw);
        println!("time: {:?}", now.elapsed());
    }

    #[test]
    fn test_fml_ell_coeffs() {
        let circuit_config =
            plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder =
            plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(circuit_config);

        let g1 = G1Affine::generator();
        let signature = G2Affine::generator();

        let fml_r_expected = miller_loop(
            Fp::get_fp_from_biguint(g1.x.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(g1.y.to_string().parse::<BigUint>().unwrap()),
            Fp2([
                Fp::get_fp_from_biguint(signature.x.c0.to_string().parse::<BigUint>().unwrap()),
                Fp::get_fp_from_biguint(signature.x.c1.to_string().parse::<BigUint>().unwrap()),
            ]),
            Fp2([
                Fp::get_fp_from_biguint(signature.y.c0.to_string().parse::<BigUint>().unwrap()),
                Fp::get_fp_from_biguint(signature.y.c1.to_string().parse::<BigUint>().unwrap()),
            ]),
            Fp2([
                Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()),
                Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
            ]),
        );

        println!("fml_r_expected is: {:?}", fml_r_expected);

        let first_ml_proof = verify_miller_loop(
            Fp::get_fp_from_biguint(g1.x.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(g1.y.to_string().parse::<BigUint>().unwrap()),
            Fp2([
                Fp::get_fp_from_biguint(signature.x.c0.to_string().parse::<BigUint>().unwrap()),
                Fp::get_fp_from_biguint(signature.x.c1.to_string().parse::<BigUint>().unwrap()),
            ]),
            Fp2([
                Fp::get_fp_from_biguint(signature.y.c0.to_string().parse::<BigUint>().unwrap()),
                Fp::get_fp_from_biguint(signature.y.c1.to_string().parse::<BigUint>().unwrap()),
            ]),
            Fp2([
                Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()),
                Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
            ]),
        );

        // G1 GENERATOR POINT
        let g1_generator: PointG1Target = [
            builder.constant_biguint(&g1.x.to_string().parse::<BigUint>().unwrap()),
            builder.constant_biguint(&g1.y.to_string().parse::<BigUint>().unwrap()),
        ];

        // SIGNATURE
        let signature: PointG2Target = calculate_ell_coeffs(&mut builder, signature);

        test_fml_output(&mut builder, first_ml_proof, &g1_generator, &signature);

        let now = Instant::now();
        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let _proof = data.prove(pw);
        println!("time: {:?}", now.elapsed());
        assert!(false)
    }

    #[test]
    fn test_verify_miller_loop() {
        let circuit_config =
            plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder =
            plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(circuit_config);

        let rng = &mut ark_std::rand::thread_rng();

        let g1 = G1Affine::generator();
        let sk: Fr = Fr::rand(rng);
        let pk = Into::<G1Affine>::into(g1 * sk);
        let message = G2Affine::rand(rng);
        let signature = Into::<G2Affine>::into(message * sk);

        // FIRST MILLER LOOP
        let first_ml_proof = verify_miller_loop(
            Fp::get_fp_from_biguint(g1.x.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(g1.y.to_string().parse::<BigUint>().unwrap()),
            Fp2([
                Fp::get_fp_from_biguint(signature.x.c0.to_string().parse::<BigUint>().unwrap()),
                Fp::get_fp_from_biguint(signature.x.c1.to_string().parse::<BigUint>().unwrap()),
            ]),
            Fp2([
                Fp::get_fp_from_biguint(signature.y.c0.to_string().parse::<BigUint>().unwrap()),
                Fp::get_fp_from_biguint(signature.y.c1.to_string().parse::<BigUint>().unwrap()),
            ]),
            Fp2([
                Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()), //change to zero
                Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
            ]),
        );

        // SECOND MILLER LOOP
        let second_ml_proof = verify_miller_loop(
            Fp::get_fp_from_biguint(pk.x.to_string().parse::<BigUint>().unwrap()),
            Fp::get_fp_from_biguint(pk.y.to_string().parse::<BigUint>().unwrap()),
            Fp2([
                Fp::get_fp_from_biguint(message.x.c0.to_string().parse::<BigUint>().unwrap()),
                Fp::get_fp_from_biguint(message.x.c1.to_string().parse::<BigUint>().unwrap()),
            ]),
            Fp2([
                Fp::get_fp_from_biguint(message.y.c0.to_string().parse::<BigUint>().unwrap()),
                Fp::get_fp_from_biguint(message.y.c1.to_string().parse::<BigUint>().unwrap()),
            ]),
            Fp2([
                Fp::get_fp_from_biguint(BigUint::from_str("1").unwrap()), //change to zero
                Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap()),
            ]),
        );

        // G1 GENERATOR POINT
        let g1_generator: PointG1Target = [
            builder.constant_biguint(&g1.x.to_string().parse::<BigUint>().unwrap()),
            builder.constant_biguint(&g1.y.to_string().parse::<BigUint>().unwrap()),
        ];

        // SIGNATURE
        let signature: PointG2Target = [
            [
                builder.constant_biguint(
                    &Fp::get_fp_from_biguint(
                        signature.x.c0.to_string().parse::<BigUint>().unwrap(),
                    )
                    .to_biguint(),
                ),
                builder.constant_biguint(
                    &Fp::get_fp_from_biguint(
                        signature.x.c1.to_string().parse::<BigUint>().unwrap(),
                    )
                    .to_biguint(),
                ),
            ],
            [
                builder.constant_biguint(
                    &Fp::get_fp_from_biguint(
                        signature.y.c0.to_string().parse::<BigUint>().unwrap(),
                    )
                    .to_biguint(),
                ),
                builder.constant_biguint(
                    &Fp::get_fp_from_biguint(
                        signature.y.c1.to_string().parse::<BigUint>().unwrap(),
                    )
                    .to_biguint(),
                ),
            ],
        ];

        // PUBLIC KEY
        let public_key: PointG1Target = [
            builder.constant_biguint(&pk.x.to_string().parse::<BigUint>().unwrap()),
            builder.constant_biguint(&pk.y.to_string().parse::<BigUint>().unwrap()),
        ];

        // MESSAGE AS G2 POINT
        let message: PointG2Target = [
            [
                builder.constant_biguint(
                    &Fp::get_fp_from_biguint(message.x.c0.to_string().parse::<BigUint>().unwrap())
                        .to_biguint(),
                ),
                builder.constant_biguint(
                    &Fp::get_fp_from_biguint(message.x.c1.to_string().parse::<BigUint>().unwrap())
                        .to_biguint(),
                ),
            ],
            [
                builder.constant_biguint(
                    &Fp::get_fp_from_biguint(message.y.c0.to_string().parse::<BigUint>().unwrap())
                        .to_biguint(),
                ),
                builder.constant_biguint(
                    &Fp::get_fp_from_biguint(message.y.c1.to_string().parse::<BigUint>().unwrap())
                        .to_biguint(),
                ),
            ],
        ];

        // let ell_coeffs = calc_pairing_precomp(g2_identity_x, g2_identity_y, g2_identity_inf);
        // let ell_coeffs_x_c0 = ell_coeffs[0][0].0[0].to_biguint();
        // let ell_coeffs_x_c1 = ell_coeffs[0][0].0[1].to_biguint();
        // let ell_coeffs_y_c0 = ell_coeffs[0][1].0[0].to_biguint();
        // let ell_coeffs_y_c1 = ell_coeffs[0][1].0[1].to_biguint();
        // let ell_coeffs_z_c0 = ell_coeffs[0][2].0[0].to_biguint();
        // let ell_coeffs_z_c1 = ell_coeffs[0][2].0[1].to_biguint();
        // println!("ell_coeffs.len() is: {:?}", ell_coeffs.len());
        // println!("ell_coeffs_x_c0 are: {:?}", ell_coeffs_x_c0);
        // println!("ell_coeffs_x_c1 are: {:?}", ell_coeffs_x_c1);
        // println!("ell_coeffs_y_c0 are: {:?}", ell_coeffs_y_c0);
        // println!("ell_coeffs_y_c1 are: {:?}", ell_coeffs_y_c1);
        // println!("ell_coeffs_z_c0 are: {:?}", ell_coeffs_z_c0);
        // println!("ell_coeffs_z_c1 are: {:?}", ell_coeffs_z_c1);
        println!("----------------------------------------------------------------");

        verify_all_proofs(
            &mut builder,
            first_ml_proof,
            second_ml_proof,
            &g1_generator,
            &signature,
            &public_key,
            &message,
        );

        let now = Instant::now();
        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let _proof = data.prove(pw);
        println!("time: {:?}", now.elapsed());
        // assert!(false)
    }
}
