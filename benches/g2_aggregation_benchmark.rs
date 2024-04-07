use ark_bls12_381::G2Affine;
use ark_ec::AffineRepr;
use ark_std::UniformRand;
use num_bigint::BigUint;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2_crypto::biguint::CircuitBuilderBiguint;
use starky_bls12_381::g2_plonky2::g2_add_unequal;
use starky_bls12_381::g2_plonky2::my_g2_add;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn aggregate_g2_points_benchmark(c: &mut Criterion) {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let circuit_config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
    let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(circuit_config);

    let rng = &mut ark_std::rand::thread_rng();
    let g2_rand_a = black_box(G2Affine::rand(rng));
    let g2_rand_b = black_box(G2Affine::rand(rng));

    let k = (g2_rand_a.x().unwrap().c0);

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

    c.bench_function("aggregation of g2 points on EC", |b| {
        b.iter(|| my_g2_add(&mut builder, &g2_rand_a, &g2_rand_b))
    });
}

criterion_group!(benches, aggregate_g2_points_benchmark);
criterion_main!(benches);
