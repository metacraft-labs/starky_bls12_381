use ark_bls12_381::G2Affine;
use ark_ec::AffineRepr;
use ark_std::UniformRand;
use num_bigint::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2_crypto::biguint::CircuitBuilderBiguint;
use starky_bls12_381::fp2_plonky2::add_fp2;
use starky_bls12_381::fp2_plonky2::inv_fp2;
use starky_bls12_381::fp2_plonky2::is_equal;
use starky_bls12_381::fp2_plonky2::is_zero;
use starky_bls12_381::fp2_plonky2::mul_fp2;
use starky_bls12_381::fp2_plonky2::range_check_fp2;
use starky_bls12_381::fp2_plonky2::sub_fp2;
use starky_bls12_381::fp_plonky2::N;
use starky_bls12_381::g2_plonky2::g2_add_unequal;
use starky_bls12_381::g2_plonky2::my_g2_add;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use starky_bls12_381::g2_plonky2::G2AdditionGenerator;
use starky_bls12_381::g2_plonky2::PointG2Target;

pub fn g2_add_unequal_isolation<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &PointG2Target,
    b: &PointG2Target,
) -> PointG2Target {
    let dy = sub_fp2(builder, &b[1], &a[1]); // u
    let dx = sub_fp2(builder, &b[0], &a[0]); // v
    let outx_c0 = builder.add_virtual_biguint_target(N);
    let outx_c1 = builder.add_virtual_biguint_target(N);
    let outy_c0 = builder.add_virtual_biguint_target(N);
    let outy_c1 = builder.add_virtual_biguint_target(N);
    let out = [[outx_c0, outx_c1], [outy_c0, outy_c1]];
    builder.add_simple_generator(G2AdditionGenerator {
        a: a.clone(),
        b: b.clone(),
        dx: dx.clone(),
        dy: dy.clone(),
        out: out.clone(),
    });
    range_check_fp2(builder, &out[0]);
    range_check_fp2(builder, &out[1]);
    let dx_sq = mul_fp2(builder, &dx, &dx); // v ^ 2 | (x2 - x1) ^ 2
    let dy_sq = mul_fp2(builder, &dy, &dy); // u ^ 2 | (y2 - y1) ^ 2

    let x1x2 = add_fp2(builder, &a[0], &b[0]); // x2 + x1
    let x1x2x3 = add_fp2(builder, &x1x2, &out[0]); // (x2 + x1) + x_r
    let cubic = mul_fp2(builder, &x1x2x3, &dx_sq); // ((x2 + x1) + x_r) * (x2 - x1) ^ 2

    let cubic_dysq = sub_fp2(builder, &cubic, &dy_sq); // (((x2 + x1) + x_r) * (x2 - x1) ^ 2) - (y2 - y1) ^ 2
    let cubic_dysq_check = is_zero(builder, &cubic_dysq);
    builder.assert_one(cubic_dysq_check.target);

    let y1y3 = add_fp2(builder, &a[1], &out[1]); // y2 + y_r
    let y1y3dx = mul_fp2(builder, &y1y3, &dx); // (y2 + y_r) * (x2 - x1)

    let x1x3 = sub_fp2(builder, &a[0], &out[0]); // x2 - x_r
    let x1x3dy = mul_fp2(builder, &x1x3, &dy); // (x2 - x_r) * (y2 - y1)

    let check = is_equal(builder, &y1y3dx, &x1x3dy);
    builder.assert_one(check.target);

    out
}

pub fn my_g2_add_isolation<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &PointG2Target,
    b: &PointG2Target,
) -> PointG2Target {
    let x1 = &a[0];
    let y1 = &a[1];
    let x2 = &b[0];
    let y2 = &b[1];

    let u = sub_fp2(builder, &y2, &y1);
    let v = sub_fp2(builder, &x2, &x1);
    let v_inv = inv_fp2(builder, &v);
    let s = mul_fp2(builder, &u, &v_inv); //  (y2 - y1) / (x2 - x1)
    let s_squared = mul_fp2(builder, &s, &s); //  ((y2 - y1) / (x2 - x1)) ^ 2
    let x_sum = add_fp2(builder, &x2, &x1); // (x2 + x1)
    let x3 = sub_fp2(builder, &s_squared, &x_sum); // (((y2 - y1) / (x2 - x1)) ^ 2) - (x2 + x1)
    let x_diff = sub_fp2(builder, &x1, &x3); // x1 - (((y2 - y1) / (x2 - x1)) ^ 2) - (x2 + x1)
    let prod = mul_fp2(builder, &s, &x_diff); // (y2 - y1) / (x2 - x1) * (x1 - (((y2 - y1) / (x2 - x1)) ^ 2) - (x2 + x1))
    let y3 = sub_fp2(builder, &prod, &y1); // ((y2 - y1) / (x2 - x1) * (x1 - (((y2 - y1) / (x2 - x1)) ^ 2) - (x2 + x1))) - y1

    /*
    [
        x: (((y2 - y1) / (x2 - x1)) ^ 2) - (x2 + x1)
        y: ((y2 - y1) / (x2 - x1) * (x1 - (((y2 - y1) / (x2 - x1)) ^ 2) - (x2 + x1))) - y1
    ]
     */
    [x3, y3]
}

fn g2_add_isolation_benchmark(c: &mut Criterion) {
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

    c.bench_function("adding g2 points in isolation", |b| {
        b.iter(|| my_g2_add(&mut builder, &g2_rand_a, &g2_rand_b))
    });
}

criterion_group!(benches, g2_add_isolation_benchmark);
criterion_main!(benches);
