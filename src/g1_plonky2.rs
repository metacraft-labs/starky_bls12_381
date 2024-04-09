use num_bigint::BigUint;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint},
    u32::arithmetic_u32::{CircuitBuilderU32, U32Target},
};
use snowbridge_milagro_bls::{PublicKey, SecretKey};

use crate::{
    fp_plonky2::{FpTarget, N},
    native::modulus,
};

pub type PointG1Target = [FpTarget; 2];

pub const PUB_KEY_LEN: usize = 48;

pub fn pk_point_check<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    point: &PointG1Target,
    pk: &[Target; PUB_KEY_LEN],
) {
    let msbs = builder.split_le(pk[0], 8);
    let bflag = msbs[6];
    builder.assert_zero(bflag.target);

    let aflag = msbs[5];

    let (x, y) = (&point[0], &point[1]);
    let two = builder.constant_biguint(&2u32.into());
    let y_2 = builder.mul_biguint(y, &two);
    let p = builder.constant_biguint(&modulus());
    let y_2_p = builder.div_biguint(&y_2, &p);
    let zero = builder.zero_u32();
    for i in 0..y_2_p.limbs.len() {
        if i == 0 {
            builder.connect(aflag.target, y_2_p.limbs[i].0);
        } else {
            builder.connect_u32(y_2_p.limbs[i], zero);
        }
    }

    let z_limbs: Vec<U32Target> = pk
        .chunks(4)
        .into_iter()
        .map(|chunk| {
            let zero = builder.zero();
            let factor = builder.constant(F::from_canonical_u32(256));
            U32Target(
                chunk
                    .iter()
                    .fold(zero, |acc, c| builder.mul_add(acc, factor, *c)),
            )
        })
        .rev()
        .collect();
    let z = BigUintTarget { limbs: z_limbs };

    let pow_2_383 = builder.constant_biguint(&(BigUint::from(1u32) << 383u32));
    let pow_2_381 = builder.constant_biguint(&(BigUint::from(1u32) << 381u32));
    let pow_2_381_or_zero = BigUintTarget {
        limbs: (0..N)
            .into_iter()
            .map(|i| U32Target(builder.select(aflag, pow_2_381.limbs[i].0, zero.0)))
            .collect(),
    };
    let flags = builder.add_biguint(&pow_2_383, &pow_2_381_or_zero);
    let z_reconstructed = builder.add_biguint(x, &flags);

    builder.connect_biguint(&z, &z_reconstructed);
}

pub fn compress_g1<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    g1_x_bits: Vec<BoolTarget>,
    g1_y_bits: Vec<BoolTarget>,
) -> PointG1Target {
    let mut u32_targets = Vec::new();
    for u32_chunk in g1_x_bits.chunks(32) {
        u32_targets.push(U32Target(builder.le_sum(u32_chunk.iter())));
    }
    let g1_x = BigUintTarget { limbs: u32_targets };
    let mut u32_targets = Vec::new();
    for u32_chunk in g1_y_bits.chunks(32) {
        u32_targets.push(U32Target(builder.le_sum(u32_chunk.iter())));
    }
    let g1_y = BigUintTarget { limbs: u32_targets };

    [g1_x, g1_y]
}

pub fn safe_pub_key_to_g1(public_key: &str, sk: SecretKey) {
    let test = hex::decode(public_key.to_string()).unwrap();
    println!("test bytes_be: {:?}", test);
    let public_key = PublicKey::from_bytes(&hex::decode(public_key.to_string()).unwrap()).unwrap();
    let milagro_public_key = PublicKey::from_secret_key(&sk);

    let g1_x = BigUint::from_bytes_be(&hex::decode(public_key.point.getx().to_string()).unwrap());
    println!("g1_x bytes_be: {:?}", g1_x);
    let g1_x = BigUint::from_bytes_le(&hex::decode(public_key.point.getx().to_string()).unwrap());
    println!("g1_x bytes_be: {:?}", g1_x);

    println!("============");
    let g1_x =
        BigUint::from_bytes_be(&hex::decode(milagro_public_key.point.getx().to_string()).unwrap());
    println!("g1_x bytes_be: {:?}", g1_x);
    let g1_x =
        BigUint::from_bytes_le(&hex::decode(milagro_public_key.point.getx().to_string()).unwrap());
    println!("g1_x bytes_be: {:?}", g1_x);
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ark_bls12_381::G1Affine;
    use ark_ec::AffineRepr;
    use ark_std::UniformRand;
    use num_bigint::BigUint;
    use plonky2::{
        field::types::Field,
        iop::{
            target::BoolTarget,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::biguint::{CircuitBuilderBiguint, WitnessBigUint};
    use snowbridge_milagro_bls::SecretKey;

    use crate::{fp_plonky2::N, g1_plonky2::safe_pub_key_to_g1, native::Fp};

    use super::{compress_g1, pk_point_check, PUB_KEY_LEN};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_pk_point_check() {
        env_logger::init();
        let x_fp = Fp::get_fp_from_biguint(BigUint::from_str(
                "1411593089133753962474730354030258013436363179669233753420355895053483563962487440344772403327192608890810553901021"
            ).unwrap());
        let y_fp = Fp::get_fp_from_biguint(BigUint::from_str("0").unwrap());
        let pk = vec![
            137, 43, 218, 171, 28, 7, 187, 176, 109, 242, 254, 250, 130, 131, 36, 52, 5, 250, 52,
            180, 134, 10, 178, 231, 178, 58, 55, 126, 255, 212, 103, 96, 128, 72, 218, 203, 176,
            158, 145, 7, 181, 216, 163, 154, 82, 112, 159, 221,
        ];
        let pk_f: Vec<F> = pk.iter().map(|i| F::from_canonical_u8(*i)).collect();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = builder.add_virtual_biguint_target(N);
        let y = builder.add_virtual_biguint_target(N);
        let point = [x, y];

        let pk = builder.add_virtual_target_arr::<PUB_KEY_LEN>();

        pk_point_check(&mut builder, &point, &pk);

        let mut pw = PartialWitness::<F>::new();
        pw.set_biguint_target(&point[0], &x_fp.to_biguint());

        pw.set_biguint_target(&point[1], &y_fp.to_biguint());

        pw.set_target_arr(&pk, &pk_f);

        builder.print_gate_counts(0);
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_g1_serialization() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let rng = &mut ark_std::rand::thread_rng();
        let g1_rand = G1Affine::rand(rng);
        let expected_g1_point = [
            builder.constant_biguint(&BigUint::try_from(*g1_rand.x().unwrap()).unwrap()),
            builder.constant_biguint(&BigUint::try_from(*g1_rand.y().unwrap()).unwrap()),
        ];

        let g1_rand_x_bits = BigUint::try_from(*g1_rand.x().unwrap())
            .unwrap()
            .to_bytes_le()
            .into_iter()
            .flat_map(|val| {
                [
                    (val >> 7) & 1,
                    (val >> 6) & 1,
                    (val >> 5) & 1,
                    (val >> 4) & 1,
                    (val >> 3) & 1,
                    (val >> 2) & 1,
                    (val >> 1) & 1,
                    (val >> 0) & 1,
                ]
                .into_iter()
            })
            .collect::<Vec<_>>();

        let g1_rand_y_bits = BigUint::try_from(*g1_rand.y().unwrap())
            .unwrap()
            .to_bytes_le()
            .into_iter()
            .flat_map(|val| {
                [
                    (val >> 7) & 1,
                    (val >> 6) & 1,
                    (val >> 5) & 1,
                    (val >> 4) & 1,
                    (val >> 3) & 1,
                    (val >> 2) & 1,
                    (val >> 1) & 1,
                    (val >> 0) & 1,
                ]
                .into_iter()
            })
            .collect::<Vec<_>>();

        let g1_rand_x_bits: Vec<BoolTarget> = g1_rand_x_bits
            .into_iter()
            .map(|f| BoolTarget::new_unsafe(builder.constant(F::from_canonical_u8(f))))
            .collect();

        let g1_rand_y_bits: Vec<BoolTarget> = g1_rand_y_bits
            .into_iter()
            .map(|f| BoolTarget::new_unsafe(builder.constant(F::from_canonical_u8(f))))
            .collect();

        let g1_x_virtual = builder.add_virtual_biguint_target(12);
        let g1_y_virtual = builder.add_virtual_biguint_target(12);
        let g1_virtual = [g1_x_virtual, g1_y_virtual];

        let pk = "8d9d1f916ffe42ec0810cd56f702d2b75b10a7f77d78646a7210cf1ee5875ba702c99a9f4e2484da9b0b31192a3bdcc8";
        let pubk = vec![
            78, 252, 122, 126, 32, 0, 75, 89, 252, 31, 42, 130, 254, 88, 6, 90, 138, 202, 135, 194,
            233, 117, 181, 75, 96, 238, 79, 100, 237, 59, 140, 111,
        ];
        let sk = SecretKey::from_bytes(&pk.to_string().as_bytes()).unwrap();
        safe_pub_key_to_g1(pk, sk);
        assert!(false);
        // let g1_x: Vec<BoolTarget> = BigUint::try_from(*g1_rand.x().unwrap())
        //     .unwrap()
        //     .to_bytes_le()
        //     .into_iter()
        //     .map(|f| BoolTarget::new_unsafe(builder.constant(F::from_canonical_u8(f))))
        //     .collect();

        // let g1_y: Vec<BoolTarget> = BigUint::try_from(*g1_rand.y().unwrap())
        //     .unwrap()
        //     .to_bytes_le()
        //     .into_iter()
        //     .map(|f| BoolTarget::new_unsafe(builder.constant(F::from_canonical_u8(f))))
        //     .collect();
        let result_g1_point = compress_g1(&mut builder, g1_rand_x_bits, g1_rand_y_bits);
        println!("expected_g1_points x is: {:?}", expected_g1_point[0]);
        println!("expected_g1_points y is: {:?}", expected_g1_point[1]);
        println!("result_g1_point x is: {:?}", result_g1_point[0]);
        println!("result_g1_point y is: {:?}", result_g1_point[1]);

        //builder.connect_biguint(&result_g1_point[0], &expected_g1_point[0]);
        //builder.connect_biguint(&result_g1_point[1], &expected_g1_point[1]);

        let mut pw = PartialWitness::<F>::new();
        pw.set_biguint_target(
            &g1_virtual[0],
            &BigUint::try_from(*g1_rand.x().unwrap()).unwrap(),
        );
        pw.set_biguint_target(
            &g1_virtual[1],
            &BigUint::try_from(*g1_rand.y().unwrap()).unwrap(),
        );
        builder.print_gate_counts(0);
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
