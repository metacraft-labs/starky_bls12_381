pub mod aggregate_proof;
pub mod native;
pub mod big_arithmetic;
pub mod fp;
pub mod fp2;
pub mod fp6;
pub mod fp12;
pub mod g1;
pub mod utils;
pub mod calc_pairing_precomp;
pub mod miller_loop;
pub mod final_exponentiate;
pub mod fp12_mul;
pub mod ecc_aggregate;
pub mod hash_to_field;
pub mod fp_plonky2;
pub mod fp2_plonky2;
pub mod hash_to_curve;
pub mod g1_plonky2;
pub mod g2_plonky2;

use crate::aggregate_proof::aggregate_proof;
fn main() {
    env_logger::init();
    std::thread::Builder::new().spawn(|| {
        aggregate_proof();
    }).unwrap().join().unwrap();
    return;
}