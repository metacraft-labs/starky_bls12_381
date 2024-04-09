use ark_bls12_381::G2Affine;
use ark_ec::AffineRepr;
use ark_std::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use num_bigint::{BigUint, ToBigUint};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::BoolTarget,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use plonky2_crypto::{biguint::CircuitBuilderBiguint, u32::arithmetic_u32::CircuitBuilderU32};
use starky_bls12_381::{
    fp2_plonky2::{is_equal, Fp2Target},
    fp_plonky2::N,
    g2_plonky2::{g2_add, g2_double, my_g2_add, PointG2Target},
};

fn test_g2_add<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &PointG2Target,
    is_infinity_a: BoolTarget,
    b: &PointG2Target,
    is_infinity_b: BoolTarget,
    iso_3_a: &Fp2Target,
    iso_3_b: &Fp2Target,
) -> PointG2Target {
    let x_equal = is_equal(builder, &a[0], &b[0]);
    let y_equal = is_equal(builder, &a[1], &b[1]);
    let do_double = builder.and(x_equal, y_equal);

    let add_input_b = [
        [
            builder.add_virtual_biguint_target(N),
            builder.add_virtual_biguint_target(N),
        ],
        [
            builder.add_virtual_biguint_target(N),
            builder.add_virtual_biguint_target(N),
        ],
    ];

    for i in 0..12 {
        if i == 0 {
            let zero = builder.zero();
            let is_zero = builder.is_equal(b[0][0].limbs[i].0, zero);
            let select = builder.select(do_double, is_zero.target, b[0][0].limbs[i].0);
            builder.connect(add_input_b[0][0].limbs[i].0, select);
        } else {
            builder.connect_u32(add_input_b[0][0].limbs[i], b[0][0].limbs[i]);
        }
    }
    builder.connect_biguint(&add_input_b[0][1], &b[0][1]);
    builder.connect_biguint(&add_input_b[1][0], &b[1][0]);
    builder.connect_biguint(&add_input_b[1][1], &b[1][1]);
    let addition = my_g2_add(builder, a, &add_input_b);
    let doubling = g2_double(builder, a, iso_3_a, iso_3_b);
    let both_inf = builder.and(is_infinity_a, is_infinity_b);
    let a_not_inf = builder.not(is_infinity_a);
    let b_not_inf = builder.not(is_infinity_b);
    let both_not_inf = builder.and(a_not_inf, b_not_inf);
    let not_y_equal = builder.not(y_equal);
    let a_neg_b = builder.and(x_equal, not_y_equal);
    let inverse = builder.and(both_not_inf, a_neg_b);
    let out_inf = builder.or(both_inf, inverse);
    builder.assert_zero(out_inf.target);
    let add_or_double_select = [
        [
            builder.add_virtual_biguint_target(N),
            builder.add_virtual_biguint_target(N),
        ],
        [
            builder.add_virtual_biguint_target(N),
            builder.add_virtual_biguint_target(N),
        ],
    ];
    for i in 0..2 {
        for j in 0..2 {
            for k in 0..N {
                let s = builder.select(
                    do_double,
                    doubling[i][j].limbs[k].0,
                    addition[i][j].limbs[k].0,
                );
                builder.connect(add_or_double_select[i][j].limbs[k].0, s);
            }
        }
    }
    let a_inf_select = [
        [
            builder.add_virtual_biguint_target(N),
            builder.add_virtual_biguint_target(N),
        ],
        [
            builder.add_virtual_biguint_target(N),
            builder.add_virtual_biguint_target(N),
        ],
    ];
    for i in 0..2 {
        for j in 0..2 {
            for k in 0..N {
                let s = builder.select(
                    is_infinity_a,
                    b[i][j].limbs[k].0,
                    add_or_double_select[i][j].limbs[k].0,
                );
                builder.connect(a_inf_select[i][j].limbs[k].0, s);
            }
        }
    }
    let b_inf_select = [
        [
            builder.add_virtual_biguint_target(N),
            builder.add_virtual_biguint_target(N),
        ],
        [
            builder.add_virtual_biguint_target(N),
            builder.add_virtual_biguint_target(N),
        ],
    ];
    for i in 0..2 {
        for j in 0..2 {
            for k in 0..N {
                let s = builder.select(
                    is_infinity_b,
                    a[i][j].limbs[k].0,
                    a_inf_select[i][j].limbs[k].0,
                );
                builder.connect(b_inf_select[i][j].limbs[k].0, s);
            }
        }
    }

    b_inf_select
}

fn g2_add_without_generator_benchmark(c: &mut Criterion) {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let circuit_config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
    let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(circuit_config);

    let rng = &mut ark_std::rand::thread_rng();
    let g2_rand_a = black_box(G2Affine::rand(rng));
    let g2_rand_b = black_box(G2Affine::rand(rng));

    let g2_rand_a = black_box([
        [
            builder.constant_biguint(&BigUint::try_from(g2_rand_a.x().unwrap().c0).unwrap()),
            builder.constant_biguint(&BigUint::try_from(g2_rand_a.x().unwrap().c1).unwrap()),
        ],
        [
            builder.constant_biguint(&BigUint::try_from(g2_rand_a.y().unwrap().c0).unwrap()),
            builder.constant_biguint(&BigUint::try_from(g2_rand_a.y().unwrap().c1).unwrap()),
        ],
    ]);

    let g2_rand_b = black_box([
        [
            builder.constant_biguint(&BigUint::try_from(g2_rand_b.x().unwrap().c0).unwrap()),
            builder.constant_biguint(&BigUint::try_from(g2_rand_b.x().unwrap().c1).unwrap()),
        ],
        [
            builder.constant_biguint(&BigUint::try_from(g2_rand_b.y().unwrap().c0).unwrap()),
            builder.constant_biguint(&BigUint::try_from(g2_rand_b.y().unwrap().c1).unwrap()),
        ],
    ]);

    let iso_3_a = black_box([
        builder.constant_biguint(&0.to_biguint().unwrap()),
        builder.constant_biguint(&240.to_biguint().unwrap()),
    ]);
    let iso_3_b = black_box([
        builder.constant_biguint(&1012.to_biguint().unwrap()),
        builder.constant_biguint(&1012.to_biguint().unwrap()),
    ]);

    let not_inf = builder._false();

    c.bench_function("g2 add without generator benchmark", |b| {
        b.iter(|| {
            test_g2_add(
                &mut builder,
                &g2_rand_a,
                not_inf,
                &g2_rand_b,
                not_inf,
                &iso_3_a,
                &iso_3_b,
            )
        })
    });
}

criterion_group!(benches, g2_add_without_generator_benchmark);
criterion_main!(benches);
