use std::{str::FromStr, cmp::min};

use itertools::Itertools;
use num_bigint::{BigUint, ToBigUint};
use plonky2::{
    field::{
        extension::{Extendable, FieldExtension},
        packed::PackedField,
        polynomial::PolynomialValues,
        types::Field,
    },
    hash::hash_types::RichField,
    iop::ext_target::ExtensionTarget,
    util::transpose,
};
use starky::{
    constraint_consumer::ConstraintConsumer,
    evaluation_frame::{StarkEvaluationFrame, StarkFrame},
    stark::Stark,
};

use crate::native::{
    add_u32_slices, add_u32_slices_12, get_bits_as_array, get_div_rem_modulus_from_biguint_12,
    get_selector_bits_from_u32, get_u32_vec_from_literal, get_u32_vec_from_literal_24, modulus,
    multiply_by_slice, sub_u32_slices, Fp, Fp2, calc_qs, calc_precomp_stuff_loop0, sub_u32_slices_12,
    mul_u32_slice_u32, mod_inverse, get_bls_12_381_parameter, calc_precomp_stuff_loop1, Fp6, Fp12,
    mul_by_nonresidue, fp4_square,
};


// Fp Multiplication layout offsets
pub const X_INPUT_OFFSET: usize = 0;
pub const Y_INPUT_OFFSET: usize = X_INPUT_OFFSET + 12;
pub const XY_OFFSET: usize = Y_INPUT_OFFSET + 12;
pub const XY_CARRIES_OFFSET: usize = XY_OFFSET + 13;
pub const SHIFTED_XY_OFFSET: usize = XY_CARRIES_OFFSET + 12;
pub const SELECTOR_OFFSET: usize = SHIFTED_XY_OFFSET + 24;
pub const SUM_OFFSET: usize = SELECTOR_OFFSET + 12;
pub const SUM_CARRIES_OFFSET: usize = SUM_OFFSET + 24;
pub const MULTIPLICATION_SELECTOR_OFFSET: usize = SUM_CARRIES_OFFSET + 24;
pub const MULTIPLICATION_FIRST_ROW_OFFSET: usize = MULTIPLICATION_SELECTOR_OFFSET + 1;

pub const FP_MULTIPLICATION_TOTAL_COLUMNS: usize = MULTIPLICATION_FIRST_ROW_OFFSET + 1;

// Non reduced addition layout offsets
pub const ADDITION_CHECK_OFFSET: usize = 0;
pub const ADDITION_X_OFFSET: usize = ADDITION_CHECK_OFFSET + 1;
pub const ADDITION_Y_OFFSET: usize = ADDITION_X_OFFSET + 24;
pub const ADDITION_SUM_OFFSET: usize = ADDITION_Y_OFFSET + 24;
pub const ADDITION_CARRY_OFFSET: usize = ADDITION_SUM_OFFSET + 24;
pub const ADDITION_TOTAL: usize = ADDITION_CARRY_OFFSET + 24;

// Non reduced subtraction layout offsets
pub const SUBTRACTION_CHECK_OFFSET: usize = 0;
pub const SUBTRACTION_X_OFFSET: usize = SUBTRACTION_CHECK_OFFSET + 1;
pub const SUBTRACTION_Y_OFFSET: usize = SUBTRACTION_X_OFFSET + 24;
pub const SUBTRACTION_DIFF_OFFSET: usize = SUBTRACTION_Y_OFFSET + 24;
pub const SUBTRACTION_BORROW_OFFSET: usize = SUBTRACTION_DIFF_OFFSET + 24;
pub const SUBTRACTION_TOTAL: usize = SUBTRACTION_BORROW_OFFSET + 24;

// Reduce and rangecheck layout offsets
pub const REDUCE_MULTIPLICATION_OFFSET: usize = 0;
pub const REDUCE_X_OFFSET: usize = REDUCE_MULTIPLICATION_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS;
pub const REDUCTION_ADDITION_OFFSET: usize = REDUCE_X_OFFSET + 24;
pub const REDUCED_OFFSET: usize = REDUCTION_ADDITION_OFFSET + ADDITION_TOTAL;
pub const REDUCTION_TOTAL: usize = REDUCED_OFFSET + 12;

// Rangecheck offsets
// whenever range check is used, start_col - 12 will contain the element being rangechecked
pub const RANGE_CHECK_SELECTOR_OFFSET: usize = 0;
pub const RANGE_CHECK_SUM_OFFSET: usize = RANGE_CHECK_SELECTOR_OFFSET + 1;
pub const RANGE_CHECK_SUM_CARRY_OFFSET: usize = RANGE_CHECK_SUM_OFFSET + 12;
pub const RANGE_CHECK_BIT_DECOMP_OFFSET: usize = RANGE_CHECK_SUM_CARRY_OFFSET + 12;
pub const RANGE_CHECK_TOTAL: usize = RANGE_CHECK_BIT_DECOMP_OFFSET + 32;

// Fp2 Multiplication layout offsets
pub const FP2_FP2_SELECTOR_OFFSET: usize = 0;
pub const FP2_FP2_X_INPUT_OFFSET: usize = FP2_FP2_SELECTOR_OFFSET + 1;
pub const FP2_FP2_Y_INPUT_OFFSET: usize = FP2_FP2_X_INPUT_OFFSET + 24;
pub const X_0_Y_0_MULTIPLICATION_OFFSET: usize = FP2_FP2_Y_INPUT_OFFSET + 24;
pub const X_1_Y_1_MULTIPLICATION_OFFSET: usize =
    X_0_Y_0_MULTIPLICATION_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS;

pub const Z1_ADD_MODULUS_OFFSET: usize =
    X_1_Y_1_MULTIPLICATION_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS;
pub const Z1_SUBTRACTION_OFFSET: usize = Z1_ADD_MODULUS_OFFSET + ADDITION_TOTAL;
pub const Z1_REDUCE_OFFSET: usize = Z1_SUBTRACTION_OFFSET + SUBTRACTION_TOTAL;
pub const Z1_RANGECHECK_OFFSET: usize = Z1_REDUCE_OFFSET + REDUCTION_TOTAL;

pub const X_0_Y_1_MULTIPLICATION_OFFSET: usize = Z1_RANGECHECK_OFFSET + RANGE_CHECK_TOTAL;
pub const X_1_Y_0_MULTIPLICATION_OFFSET: usize =
    X_0_Y_1_MULTIPLICATION_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS;

pub const Z2_ADDITION_OFFSET: usize =
    X_1_Y_0_MULTIPLICATION_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS;
pub const Z2_REDUCE_OFFSET: usize = Z2_ADDITION_OFFSET + ADDITION_TOTAL;
pub const Z2_RANGECHECK_OFFSET: usize = Z2_REDUCE_OFFSET + REDUCTION_TOTAL;

pub const TOTAL_COLUMNS_FP2_MULTIPLICATION: usize = Z2_RANGECHECK_OFFSET + RANGE_CHECK_TOTAL;

// Fp2 * Fp multiplication layout offsets
pub const FP2_FP_MUL_SELECTOR_OFFSET: usize = 0;
pub const FP2_FP_X_INPUT_OFFSET: usize = FP2_FP_MUL_SELECTOR_OFFSET + 1;
pub const FP2_FP_Y_INPUT_OFFSET: usize = FP2_FP_X_INPUT_OFFSET + 24;
pub const X0_Y_MULTIPLICATION_OFFSET:  usize = FP2_FP_Y_INPUT_OFFSET + 12;
pub const X0_Y_REDUCE_OFFSET: usize = X0_Y_MULTIPLICATION_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS;
pub const X0_Y_RANGECHECK_OFFSET: usize = X0_Y_REDUCE_OFFSET + REDUCTION_TOTAL;
pub const X1_Y_MULTIPLICATION_OFFSET:  usize = X0_Y_RANGECHECK_OFFSET + RANGE_CHECK_TOTAL;
pub const X1_Y_REDUCE_OFFSET: usize = X1_Y_MULTIPLICATION_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS;
pub const X1_Y_RANGECHECK_OFFSET: usize = X1_Y_REDUCE_OFFSET + REDUCTION_TOTAL;
pub const FP2_FP_TOTAL_COLUMNS: usize = X1_Y_RANGECHECK_OFFSET + RANGE_CHECK_TOTAL;

// Fp addition layout offsets
pub const FP_ADDITION_CHECK_OFFSET: usize = 0;
pub const FP_ADDITION_X_OFFSET: usize = FP_ADDITION_CHECK_OFFSET + 1;
pub const FP_ADDITION_Y_OFFSET: usize = FP_ADDITION_X_OFFSET + 12;
pub const FP_ADDITION_SUM_OFFSET: usize = FP_ADDITION_Y_OFFSET + 12;
pub const FP_ADDITION_CARRY_OFFSET: usize = FP_ADDITION_SUM_OFFSET + 12;
pub const FP_ADDITION_TOTAL: usize = FP_ADDITION_CARRY_OFFSET + 12;

// Fp subtraction layout offsets
pub const FP_SUBTRACTION_CHECK_OFFSET: usize = 0;
pub const FP_SUBTRACTION_X_OFFSET: usize = FP_SUBTRACTION_CHECK_OFFSET + 1;
pub const FP_SUBTRACTION_Y_OFFSET: usize = FP_SUBTRACTION_X_OFFSET + 12;
pub const FP_SUBTRACTION_DIFF_OFFSET: usize = FP_SUBTRACTION_Y_OFFSET + 12;
pub const FP_SUBTRACTION_BORROW_OFFSET: usize = FP_SUBTRACTION_DIFF_OFFSET + 12;
pub const FP_SUBTRACTION_TOTAL: usize = FP_SUBTRACTION_BORROW_OFFSET + 12;

// Fp2 addition layout offsets
pub const FP2_ADDITION_0_OFFSET: usize = 0;
pub const FP2_ADDITION_1_OFFSET: usize = FP2_ADDITION_0_OFFSET + FP_ADDITION_TOTAL;
pub const FP2_ADDITION_TOTAL: usize = FP2_ADDITION_1_OFFSET + FP_ADDITION_TOTAL;

// Fp2 subtraction layout offsets
pub const FP2_SUBTRACTION_0_OFFSET: usize = 0;
pub const FP2_SUBTRACTION_1_OFFSET: usize = FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_TOTAL;
pub const FP2_SUBTRACTION_TOTAL: usize = FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_TOTAL;

// Fp multiply single
pub const FP_MULTIPLY_SINGLE_CHECK_OFFSET: usize = 0;
pub const FP_MULTIPLY_SINGLE_X_OFFSET: usize = FP_MULTIPLY_SINGLE_CHECK_OFFSET + 1;
pub const FP_MULTIPLY_SINGLE_Y_OFFSET: usize = FP_MULTIPLY_SINGLE_X_OFFSET + 12;
pub const FP_MULTIPLY_SINGLE_SUM_OFFSET: usize = FP_MULTIPLY_SINGLE_Y_OFFSET + 1;
pub const FP_MULTIPLY_SINGLE_CARRY_OFFSET: usize = FP_MULTIPLY_SINGLE_SUM_OFFSET + 12;
pub const FP_MULTIPLY_SINGLE_TOTAL: usize = FP_MULTIPLY_SINGLE_CARRY_OFFSET + 12;

// Fp2 multiply single
pub const FP2_MULTIPLY_SINGLE_0_OFFSET: usize = 0;
pub const FP2_MULTIPLY_SINGLE_1_OFFSET: usize = FP2_MULTIPLY_SINGLE_0_OFFSET + FP_MULTIPLY_SINGLE_TOTAL;
pub const FP2_MULTIPLY_SINGLE_TOTAL: usize = FP2_MULTIPLY_SINGLE_1_OFFSET + FP_MULTIPLY_SINGLE_TOTAL;

// Fp reduce rangecheck single
pub const FP_SINGLE_REDUCE_MULTIPLICATION_OFFSET: usize = 0;
pub const FP_SINGLE_REDUCE_X_OFFSET: usize = FP_SINGLE_REDUCE_MULTIPLICATION_OFFSET + FP_MULTIPLY_SINGLE_TOTAL;
pub const FP_SINGLE_REDUCTION_ADDITION_OFFSET: usize = FP_SINGLE_REDUCE_X_OFFSET + 12;
pub const FP_SINGLE_REDUCED_OFFSET: usize = FP_SINGLE_REDUCTION_ADDITION_OFFSET + FP_ADDITION_TOTAL;
pub const FP_SINGLE_REDUCE_TOTAL: usize = FP_SINGLE_REDUCED_OFFSET + 12;

// FP2 non residue multiplication
pub const FP2_NON_RESIDUE_MUL_CHECK_OFFSET: usize = 0;
pub const FP2_NON_RESIDUE_MUL_INPUT_OFFSET: usize = FP2_NON_RESIDUE_MUL_CHECK_OFFSET + 1;
pub const FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET: usize = FP2_NON_RESIDUE_MUL_INPUT_OFFSET + 24;
pub const FP2_NON_RESIDUE_MUL_Z0_REDUCE_OFFSET: usize = FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_TOTAL + FP_SUBTRACTION_TOTAL;
pub const FP2_NON_RESIDUE_MUL_Z0_RANGECHECK_OFFSET: usize = FP2_NON_RESIDUE_MUL_Z0_REDUCE_OFFSET + FP_SINGLE_REDUCE_TOTAL;
pub const FP2_NON_RESIDUE_MUL_C0_C1_ADD_OFFSET: usize = FP2_NON_RESIDUE_MUL_Z0_RANGECHECK_OFFSET + RANGE_CHECK_TOTAL;
pub const FP2_NON_RESIDUE_MUL_Z1_REDUCE_OFFSET: usize = FP2_NON_RESIDUE_MUL_C0_C1_ADD_OFFSET + FP_ADDITION_TOTAL;
pub const FP2_NON_RESIDUE_MUL_Z1_RANGECHECK_OFFSET: usize = FP2_NON_RESIDUE_MUL_Z1_REDUCE_OFFSET + FP_SINGLE_REDUCE_TOTAL;
pub const FP2_NON_RESIDUE_MUL_TOTAL: usize = FP2_NON_RESIDUE_MUL_Z1_RANGECHECK_OFFSET + RANGE_CHECK_TOTAL;

// FP6 multiplication offsets
pub const FP6_MUL_SELECTOR_OFFSET: usize = 0;
pub const FP6_MUL_X_INPUT_OFFSET: usize = FP6_MUL_SELECTOR_OFFSET + 1;
pub const FP6_MUL_Y_INPUT_OFFSET: usize = FP6_MUL_X_INPUT_OFFSET + 24*3;
pub const FP6_MUL_T0_CALC_OFFSET: usize = FP6_MUL_Y_INPUT_OFFSET + 24*3;
pub const FP6_MUL_T1_CALC_OFFSET: usize = FP6_MUL_T0_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;
pub const FP6_MUL_T2_CALC_OFFSET: usize = FP6_MUL_T1_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;
pub const FP6_MUL_T3_CALC_OFFSET: usize = FP6_MUL_T2_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;
pub const FP6_MUL_T4_CALC_OFFSET: usize = FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_T5_CALC_OFFSET: usize = FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_T6_CALC_OFFSET: usize = FP6_MUL_T5_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;
pub const FP6_MUL_T7_CALC_OFFSET: usize = FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_T8_CALC_OFFSET: usize = FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_X_CALC_OFFSET: usize = FP6_MUL_T8_CALC_OFFSET + FP2_NON_RESIDUE_MUL_TOTAL;
pub const FP6_MUL_T9_CALC_OFFSET: usize = FP6_MUL_X_CALC_OFFSET + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_T10_CALC_OFFSET: usize = FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_T11_CALC_OFFSET: usize = FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_T12_CALC_OFFSET: usize = FP6_MUL_T11_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;
pub const FP6_MUL_T13_CALC_OFFSET: usize = FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_T14_CALC_OFFSET: usize = FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_Y_CALC_OFFSET: usize = FP6_MUL_T14_CALC_OFFSET + FP2_NON_RESIDUE_MUL_TOTAL;
pub const FP6_MUL_T15_CALC_OFFSET: usize = FP6_MUL_Y_CALC_OFFSET + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_T16_CALC_OFFSET: usize = FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_T17_CALC_OFFSET: usize = FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_T18_CALC_OFFSET: usize = FP6_MUL_T17_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;
pub const FP6_MUL_T19_CALC_OFFSET: usize = FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_Z_CALC_OFFSET: usize = FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;
pub const FP6_MUL_TOTAL_COLUMNS: usize = FP6_MUL_Z_CALC_OFFSET + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*2;

// FP6 non residue multiplication
pub const FP6_NON_RESIDUE_MUL_CHECK_OFFSET: usize = 0;
pub const FP6_NON_RESIDUE_MUL_INPUT_OFFSET: usize = FP6_NON_RESIDUE_MUL_CHECK_OFFSET + 1;
pub const FP6_NON_RESIDUE_MUL_C2: usize = FP6_NON_RESIDUE_MUL_INPUT_OFFSET + 24*3;
pub const FP6_NON_RESIDUE_MUL_TOTAL: usize = FP6_NON_RESIDUE_MUL_C2 + FP2_NON_RESIDUE_MUL_TOTAL;

// FP6 add
pub const FP6_ADDITION_0_OFFSET: usize = 0;
pub const FP6_ADDITION_1_OFFSET: usize = FP6_ADDITION_0_OFFSET + FP2_ADDITION_TOTAL;
pub const FP6_ADDITION_2_OFFSET: usize = FP6_ADDITION_1_OFFSET + FP2_ADDITION_TOTAL;
pub const FP6_ADDITION_TOTAL: usize = FP6_ADDITION_2_OFFSET + FP2_ADDITION_TOTAL;

// FP6 add
pub const FP6_SUBTRACTION_0_OFFSET: usize = 0;
pub const FP6_SUBTRACTION_1_OFFSET: usize = FP6_SUBTRACTION_0_OFFSET + FP2_SUBTRACTION_TOTAL;
pub const FP6_SUBTRACTION_2_OFFSET: usize = FP6_SUBTRACTION_1_OFFSET + FP2_SUBTRACTION_TOTAL;
pub const FP6_SUBTRACTION_TOTAL: usize = FP6_SUBTRACTION_2_OFFSET + FP2_SUBTRACTION_TOTAL;

// FP12 multiplication offsets
pub const FP12_MUL_SELECTOR_OFFSET: usize = 0;
pub const FP12_MUL_X_INPUT_OFFSET: usize = FP12_MUL_SELECTOR_OFFSET + 1;
pub const FP12_MUL_Y_INPUT_OFFSET: usize = FP12_MUL_X_INPUT_OFFSET + 24*3*2;
pub const FP12_MUL_T0_CALC_OFFSET: usize = FP12_MUL_Y_INPUT_OFFSET + 24*3*2;
pub const FP12_MUL_T1_CALC_OFFSET: usize = FP12_MUL_T0_CALC_OFFSET + FP6_MUL_TOTAL_COLUMNS;
pub const FP12_MUL_T2_CALC_OFFSET: usize = FP12_MUL_T1_CALC_OFFSET + FP6_MUL_TOTAL_COLUMNS;
pub const FP12_MUL_X_CALC_OFFSET: usize = FP12_MUL_T2_CALC_OFFSET + FP6_NON_RESIDUE_MUL_TOTAL;
pub const FP12_MUL_T3_CALC_OFFSET: usize = FP12_MUL_X_CALC_OFFSET + FP6_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*6;
pub const FP12_MUL_T4_CALC_OFFSET: usize = FP12_MUL_T3_CALC_OFFSET + FP6_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*6;
pub const FP12_MUL_T5_CALC_OFFSET: usize = FP12_MUL_T4_CALC_OFFSET + FP6_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*6;
pub const FP12_MUL_T6_CALC_OFFSET: usize = FP12_MUL_T5_CALC_OFFSET + FP6_MUL_TOTAL_COLUMNS;
pub const FP12_MUL_Y_CALC_OFFSET: usize = FP12_MUL_T6_CALC_OFFSET + FP6_ADDITION_TOTAL + FP6_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*6;
pub const FP12_MUL_TOTAL_COLUMNS: usize = FP12_MUL_Y_CALC_OFFSET + FP6_ADDITION_TOTAL + FP6_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*6;

// Forbenius map Fp2
pub const FP2_FORBENIUS_MAP_SELECTOR_OFFSET: usize = 0;
pub const FP2_FORBENIUS_MAP_INPUT_OFFSET: usize = FP2_FORBENIUS_MAP_SELECTOR_OFFSET + 1;
pub const FP2_FORBENIUS_MAP_POW_OFFSET: usize = FP2_FORBENIUS_MAP_INPUT_OFFSET + 24;
pub const FP2_FORBENIUS_MAP_DIV_OFFSET: usize = FP2_FORBENIUS_MAP_POW_OFFSET + 1;
pub const FP2_FORBENIUS_MAP_REM_OFFSET: usize = FP2_FORBENIUS_MAP_DIV_OFFSET + 1;
pub const FP2_FORBENIUS_MAP_T0_CALC_OFFSET: usize = FP2_FORBENIUS_MAP_REM_OFFSET + 1;
pub const FP2_FORBENIUS_MAP_MUL_RES_ROW: usize = FP2_FORBENIUS_MAP_T0_CALC_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS + REDUCTION_TOTAL + RANGE_CHECK_TOTAL;
pub const FP2_FORBENIUS_MAP_ROW_NUM: usize = FP2_FORBENIUS_MAP_MUL_RES_ROW + 1;
pub const FP2_FORBENIUS_MAP_TOTAL_COLUMNS: usize = FP2_FORBENIUS_MAP_ROW_NUM + 1;

// Forbenius map Fp6
pub const FP6_FORBENIUS_MAP_SELECTOR_OFFSET: usize = 0;
pub const FP6_FORBENIUS_MAP_INPUT_OFFSET: usize = FP6_FORBENIUS_MAP_SELECTOR_OFFSET + 1;
pub const FP6_FORBENIUS_MAP_POW_OFFSET: usize = FP6_FORBENIUS_MAP_INPUT_OFFSET + 24*3;
pub const FP6_FORBENIUS_MAP_DIV_OFFSET: usize = FP6_FORBENIUS_MAP_POW_OFFSET + 1;
pub const FP6_FORBENIUS_MAP_REM_OFFSET: usize = FP6_FORBENIUS_MAP_DIV_OFFSET + 1;
pub const FP6_FORBENIUS_MAP_BIT0_OFFSET: usize = FP6_FORBENIUS_MAP_REM_OFFSET + 1;
pub const FP6_FORBENIUS_MAP_BIT1_OFFSET: usize = FP6_FORBENIUS_MAP_BIT0_OFFSET + 1;
pub const FP6_FORBENIUS_MAP_BIT2_OFFSET: usize = FP6_FORBENIUS_MAP_BIT1_OFFSET + 1;
pub const FP6_FORBENIUS_MAP_X_CALC_OFFSET: usize = FP6_FORBENIUS_MAP_BIT2_OFFSET + 1;
pub const FP6_FORBENIUS_MAP_T0_CALC_OFFSET: usize = FP6_FORBENIUS_MAP_X_CALC_OFFSET + FP2_FORBENIUS_MAP_TOTAL_COLUMNS;
pub const FP6_FORBENIUS_MAP_Y_CALC_OFFSET: usize = FP6_FORBENIUS_MAP_T0_CALC_OFFSET + FP2_FORBENIUS_MAP_TOTAL_COLUMNS;
pub const FP6_FORBENIUS_MAP_T1_CALC_OFFSET: usize = FP6_FORBENIUS_MAP_Y_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;
pub const FP6_FORBENIUS_MAP_Z_CALC_OFFSET: usize = FP6_FORBENIUS_MAP_T1_CALC_OFFSET + FP2_FORBENIUS_MAP_TOTAL_COLUMNS;
pub const FP6_FORBENIUS_MAP_TOTAL_COLUMNS: usize = FP6_FORBENIUS_MAP_Z_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;

// Forbenius map Fp12
pub const FP12_FORBENIUS_MAP_SELECTOR_OFFSET: usize = 0;
pub const FP12_FORBENIUS_MAP_INPUT_OFFSET: usize = FP12_FORBENIUS_MAP_SELECTOR_OFFSET + 1;
pub const FP12_FORBENIUS_MAP_POW_OFFSET: usize = FP12_FORBENIUS_MAP_INPUT_OFFSET + 24*3*2;
pub const FP12_FORBENIUS_MAP_DIV_OFFSET: usize = FP12_FORBENIUS_MAP_POW_OFFSET + 1;
pub const FP12_FORBENIUS_MAP_REM_OFFSET: usize = FP12_FORBENIUS_MAP_DIV_OFFSET + 1;
pub const FP12_FORBENIUS_MAP_BIT0_OFFSET: usize = FP12_FORBENIUS_MAP_REM_OFFSET + 1;
pub const FP12_FORBENIUS_MAP_BIT1_OFFSET: usize = FP12_FORBENIUS_MAP_BIT0_OFFSET + 1;
pub const FP12_FORBENIUS_MAP_BIT2_OFFSET: usize = FP12_FORBENIUS_MAP_BIT1_OFFSET + 1;
pub const FP12_FORBENIUS_MAP_BIT3_OFFSET: usize = FP12_FORBENIUS_MAP_BIT2_OFFSET + 1;
pub const FP12_FORBENIUS_MAP_R0_CALC_OFFSET: usize = FP12_FORBENIUS_MAP_BIT3_OFFSET + 1;
pub const FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET: usize = FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_TOTAL_COLUMNS;
pub const FP12_FORBENIUS_MAP_C0_CALC_OFFSET: usize = FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET + FP6_FORBENIUS_MAP_TOTAL_COLUMNS;
pub const FP12_FORBENIUS_MAP_C1_CALC_OFFSET: usize = FP12_FORBENIUS_MAP_C0_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;
pub const FP12_FORBENIUS_MAP_C2_CALC_OFFSET: usize = FP12_FORBENIUS_MAP_C1_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;
pub const FP12_FORBENIUS_MAP_TOTAL_COLUMNS: usize = FP12_FORBENIUS_MAP_C2_CALC_OFFSET + TOTAL_COLUMNS_FP2_MULTIPLICATION;

pub const TOTAL_COLUMNS: usize = FP12_FORBENIUS_MAP_TOTAL_COLUMNS;
pub const COLUMNS: usize = TOTAL_COLUMNS;

pub const PIS_INPUT_OFFSET: usize = 0;
pub const PIS_POW_OFFSET: usize = PIS_INPUT_OFFSET + 24*3*2;
pub const PIS_RES_OFFSET: usize = PIS_POW_OFFSET + 1;
pub const PUBLIC_INPUTS: usize = PIS_RES_OFFSET + 24*3*2;

macro_rules! bit_decomp_32 {
    ($row:expr, $col:expr, $f:ty, $p:ty) => {
        ((0..32).fold(<$p>::ZEROS, |acc, i| {
            acc + $row[$col + i] * <$f>::from_canonical_u64(1 << i)
        }))
    };
}

// A (Fp) * B (Fp) => C (Fp)
#[derive(Clone)]
pub struct ForbeniusMapStark<F: RichField + Extendable<D>, const D: usize> {
    pub trace: Vec<[F; TOTAL_COLUMNS]>,
    num_rows: usize,
}

// Implement trace generator
impl<F: RichField + Extendable<D>, const D: usize> ForbeniusMapStark<F, D> {
    pub fn new(num_rows: usize) -> Self {
        Self {
            trace: vec![[F::ZERO; TOTAL_COLUMNS]; num_rows],
            num_rows,
        }
    }

    pub fn assign_u32_12(&mut self, row: usize, start_col: usize, val: [u32; 12]) {
        for i in 0..12 {
            self.trace[row][start_col + i] = F::from_canonical_u32(val[i]);
        }
    }

    pub fn assign_u32_in_series(&mut self, row: usize, start_col: usize, val: &[u32]) {
        for i in 0..val.len() {
            self.trace[row][start_col + i] = F::from_canonical_u32(val[i]);
        }
    }

    pub fn assign_cols_from_prev(&mut self, row: usize, start_col: usize, num_cols: usize) {
        assert!(row >= 1);
        for i in start_col..start_col + num_cols {
            self.trace[row][start_col + i] = self.trace[row - 1][start_col + i];
        }
    }

    pub fn fill_addition_trace(
        &mut self,
        x: &[u32; 24],
        y: &[u32; 24],
        row: usize,
        start_col: usize,
    ) {
        self.trace[row][start_col + ADDITION_CHECK_OFFSET] = F::ONE;
        let (x_y_sum, x_y_sum_carry) = add_u32_slices(&x, &y);
        self.assign_u32_in_series(row, start_col + ADDITION_X_OFFSET, x);
        self.assign_u32_in_series(row, start_col + ADDITION_Y_OFFSET, y);
        self.assign_u32_in_series(row, start_col + ADDITION_SUM_OFFSET, &x_y_sum);
        self.assign_u32_in_series(row, start_col + ADDITION_CARRY_OFFSET, &x_y_sum_carry);
    }

    pub fn fill_trace_addition_fp(
        &mut self,
        x: &[u32; 12],
        y: &[u32; 12],
        row: usize,
        start_col: usize,
    ) {
        self.trace[row][start_col + FP_ADDITION_CHECK_OFFSET] = F::ONE;
        let (x_y_sum, x_y_sum_carry) = add_u32_slices_12(&x, &y);
        self.assign_u32_in_series(row, start_col + FP_ADDITION_X_OFFSET, x);
        self.assign_u32_in_series(row, start_col + FP_ADDITION_Y_OFFSET, y);
        self.assign_u32_in_series(row, start_col + FP_ADDITION_SUM_OFFSET, &x_y_sum);
        self.assign_u32_in_series(row, start_col + FP_ADDITION_CARRY_OFFSET, &x_y_sum_carry);
    }

    pub fn fill_trace_negate_fp(
        &mut self,
        x: &[u32; 12],
        row: usize,
        start_col: usize
    ) {
        let minus_x = (-Fp(x.to_owned())).0;
        self.fill_trace_addition_fp(x, &minus_x, row, start_col);
    }

    pub fn fill_trace_subtraction_fp(
        &mut self,
        x: &[u32; 12],
        y: &[u32; 12],
        row: usize,
        start_col: usize,
    ) {
        self.trace[row][start_col + FP_SUBTRACTION_CHECK_OFFSET] = F::ONE;
        let (x_y_diff, x_y_borrow) = sub_u32_slices_12(&x, &y);
        self.assign_u32_in_series(row, start_col + FP_SUBTRACTION_X_OFFSET, x);
        self.assign_u32_in_series(row, start_col + FP_SUBTRACTION_Y_OFFSET, y);
        self.assign_u32_in_series(row, start_col + FP_SUBTRACTION_DIFF_OFFSET, &x_y_diff);
        self.assign_u32_in_series(row, start_col + FP_SUBTRACTION_BORROW_OFFSET, &x_y_borrow);
    }

    pub fn fill_trace_multiply_single_fp(
        &mut self,
        x: &[u32; 12],
        y: u32,
        row: usize,
        start_col: usize,
    ) {
        self.trace[row][start_col + FP_MULTIPLY_SINGLE_CHECK_OFFSET] = F::ONE;
        let (x_y_sum, x_y_carry) = mul_u32_slice_u32(x, y);
        self.assign_u32_in_series(row, start_col + FP_MULTIPLY_SINGLE_X_OFFSET, x);
        self.trace[row][start_col + FP_MULTIPLY_SINGLE_Y_OFFSET] = F::from_canonical_u32(y);
        self.assign_u32_in_series(row, start_col + FP_MULTIPLY_SINGLE_SUM_OFFSET, &x_y_sum);
        self.assign_u32_in_series(row, start_col + FP_MULTIPLY_SINGLE_CARRY_OFFSET, &x_y_carry);
    }

    pub fn fill_trace_reduce_single(
        &mut self,
        x: &[u32; 12],
        row: usize,
        start_col: usize,
    ) -> [u32; 12] {
        let (div, rem) = get_div_rem_modulus_from_biguint_12(BigUint::new(x.to_vec()));
        let div = div[0];
        let modulus = get_u32_vec_from_literal(modulus());
        self.fill_trace_multiply_single_fp(&modulus, div, row, start_col + FP_SINGLE_REDUCE_MULTIPLICATION_OFFSET);
        self.assign_u32_in_series(row, start_col + FP_SINGLE_REDUCE_X_OFFSET, x);
        let div_x_mod = get_u32_vec_from_literal(div.to_biguint().unwrap() * BigUint::new(modulus.to_vec()));
        self.assign_u32_in_series(row, start_col + FP_SINGLE_REDUCED_OFFSET, &rem);
        self.fill_trace_addition_fp(&div_x_mod, &rem, row, start_col + FP_SINGLE_REDUCTION_ADDITION_OFFSET);
        rem
    }

    pub fn fill_trace_addition_fp2(
        &mut self,
        x: &[[u32; 12]; 2],
        y: &[[u32; 12]; 2],
        row: usize,
        start_col: usize,
    ) {
        self.fill_trace_addition_fp(&x[0], &y[0], row, start_col + FP2_ADDITION_0_OFFSET);
        self.fill_trace_addition_fp(&x[1], &y[1], row, start_col + FP2_ADDITION_1_OFFSET);
    }

    pub fn fill_trace_subtraction_fp2(
        &mut self,
        x: &[[u32; 12]; 2],
        y: &[[u32; 12]; 2],
        row: usize,
        start_col: usize,
    ) {
        self.fill_trace_subtraction_fp(&x[0], &y[0], row, start_col + FP2_SUBTRACTION_0_OFFSET);
        self.fill_trace_subtraction_fp(&x[1], &y[1], row, start_col + FP2_SUBTRACTION_1_OFFSET);
    }

    pub fn fill_trace_multiply_single_fp2(
        &mut self,
        x: &[[u32; 12]; 2],
        y: &[u32; 2],
        row: usize,
        start_col: usize,
    ) {
        self.fill_trace_multiply_single_fp(&x[0], y[0], row, start_col + FP2_SUBTRACTION_0_OFFSET);
        self.fill_trace_multiply_single_fp(&x[1], y[1], row, start_col + FP2_SUBTRACTION_1_OFFSET);
    }

    pub fn fill_trace_negate_fp2(
        &mut self,
        x: &[[u32; 12]; 2],
        row: usize,
        start_col: usize
    ) {
        let minus_x: [[u32; 12]; 2] = (-Fp2([Fp(x[0].to_owned()), Fp(x[1].to_owned())])).0.iter().map(|x| x.0).collect::<Vec<[u32; 12]>>().try_into().unwrap();
        self.fill_trace_addition_fp2(x, &minus_x, row, start_col);
    }

    pub fn fill_subtraction_trace(
        &mut self,
        x: &[u32; 24],
        y: &[u32; 24],
        row: usize,
        start_col: usize,
    ) {
        self.trace[row][start_col + SUBTRACTION_CHECK_OFFSET] = F::ONE;
        let (x_y_diff, x_y_diff_borrow) = sub_u32_slices(&x, &y);
        self.assign_u32_in_series(row, start_col + SUBTRACTION_X_OFFSET, x);
        self.assign_u32_in_series(row, start_col + SUBTRACTION_Y_OFFSET, y);
        self.assign_u32_in_series(row, start_col + SUBTRACTION_DIFF_OFFSET, &x_y_diff);
        self.assign_u32_in_series(row, start_col + SUBTRACTION_BORROW_OFFSET, &x_y_diff_borrow);
    }

    pub fn fill_range_check_trace(&mut self, x: &[u32; 12], row: usize, start_col: usize) {
        let y = (BigUint::from(1u32) << 382) - modulus();
        let y_u32 = get_u32_vec_from_literal(y);
        let (x_y_sum, x_y_carry) = add_u32_slices_12(&x, &y_u32);
        self.trace[row][start_col + RANGE_CHECK_SELECTOR_OFFSET] = F::ONE;
        self.assign_u32_in_series(row, start_col + RANGE_CHECK_SUM_OFFSET, &x_y_sum);
        self.assign_u32_in_series(row, start_col + RANGE_CHECK_SUM_CARRY_OFFSET, &x_y_carry);
        self.assign_u32_in_series(
            row,
            start_col + RANGE_CHECK_BIT_DECOMP_OFFSET,
            &get_bits_as_array(x_y_sum[11]),
        );
    }

    // Fills from start_row..end_row+1
    pub fn fill_multiplication_trace_no_mod_reduction(
        &mut self,
        x: &[u32; 12],
        y: &[u32; 12],
        start_row: usize,
        end_row: usize,
        start_col: usize,
    ) {
        // [TODO]:
        // 1. Assert end_row - start_row + 1 == total rows required
        // 2. Assert end_col - start_col + 1 == total cols required
        // assert_eq!(end_row - start_row + 1, self.num_rows);
        let mut selector = 1;
        // Inputs are filled from start_row..end_row + 1
        self.trace[start_row][start_col + MULTIPLICATION_FIRST_ROW_OFFSET] = F::ONE;
        for i in start_row..start_row + 11 {
            self.trace[i][start_col + MULTIPLICATION_SELECTOR_OFFSET] = F::ONE;
        }
        for row in start_row..end_row + 1 {
            self.assign_u32_in_series(row, start_col + X_INPUT_OFFSET, x);
            self.assign_u32_in_series(row, start_col + Y_INPUT_OFFSET, y);
            let selector_u32 = get_selector_bits_from_u32(selector);
            self.assign_u32_in_series(row, start_col + SELECTOR_OFFSET, &selector_u32);
            selector *= 2;
        }

        // We have calcualted multiplying two max bls12_381 Fp numbers
        // dont exceed [u32; 24] so no need of [u32; 25]
        let mut prev_xy_sum = [0u32; 24];

        for i in 0..12 {
            let (xy, xy_carry) = multiply_by_slice(&x, y[i]);
            self.assign_u32_in_series(start_row + i, start_col + XY_OFFSET, &xy);
            self.assign_u32_in_series(start_row + i, start_col + XY_CARRIES_OFFSET, &xy_carry);

            // fill shifted XY's
            // XY's will have 0-11 number of shifts in their respective rows
            let mut xy_shifted = [0u32; 24];
            for j in 0..13 {
                let shift = i;
                xy_shifted[j + shift] = xy[j];
            }
            self.assign_u32_in_series(start_row + i, start_col + SHIFTED_XY_OFFSET, &xy_shifted);

            // Fill XY_SUM, XY_SUM_CARRIES
            let (xy_sum, xy_sum_carry) = add_u32_slices(&xy_shifted, &prev_xy_sum);
            self.assign_u32_in_series(start_row + i, start_col + SUM_OFFSET, &xy_sum);
            self.assign_u32_in_series(start_row + i, start_col + SUM_CARRIES_OFFSET, &xy_sum_carry);

            prev_xy_sum = xy_sum;
        }
    }

    fn fill_reduction_trace(
        &mut self,
        x: &[u32; 24],
        start_row: usize,
        end_row: usize,
        start_col: usize,
    ) -> [u32; 12] {
        let (div, rem) = get_div_rem_modulus_from_biguint_12(BigUint::new(x.to_vec()));
        let modulus = get_u32_vec_from_literal(modulus());
        self.fill_multiplication_trace_no_mod_reduction(
            &div,
            &modulus,
            start_row,
            end_row,
            start_col + REDUCE_MULTIPLICATION_OFFSET,
        );

        for row in start_row..end_row + 1 {
            self.assign_u32_in_series(row, start_col + REDUCE_X_OFFSET, x);
        }

        let div_x_mod = get_u32_vec_from_literal_24(
            BigUint::new(div.to_vec()) * BigUint::new(modulus.to_vec()),
        );

        for i in start_row..end_row + 1 {
            self.assign_u32_in_series(i, start_col + REDUCED_OFFSET, &rem);
        }
        let mut rem_24 = [0u32; 24];
        rem_24[0..12].copy_from_slice(&rem);

        self.fill_addition_trace(
            &div_x_mod,
            &rem_24,
            start_row + 11,
            start_col + REDUCTION_ADDITION_OFFSET,
        );
        // println!("rem {:?}", rem_24);
        rem

    }


    pub fn generate_trace_fp2_mul(&mut self, x: [[u32; 12]; 2], y: [[u32; 12]; 2], start_row: usize, end_row: usize,start_col: usize) {
        let modulus = modulus();

        for i in start_row..end_row+1 {
            self.trace[i][start_col + FP2_FP2_SELECTOR_OFFSET] = F::ONE;
            self.assign_u32_in_series(i, start_col + FP2_FP2_X_INPUT_OFFSET, &x[0]);
            self.assign_u32_in_series(i, start_col + FP2_FP2_X_INPUT_OFFSET+12, &x[1]);
            self.assign_u32_in_series(i, start_col + FP2_FP2_Y_INPUT_OFFSET, &y[0]);
            self.assign_u32_in_series(i, start_col + FP2_FP2_Y_INPUT_OFFSET+12, &y[1]);
        }
        self.trace[end_row][start_col + FP2_FP2_SELECTOR_OFFSET] = F::ZERO;
        // filling trace for X0*Y0 - X1*Y1
        self.fill_multiplication_trace_no_mod_reduction(
            &x[0],
            &y[0],
            start_row,
            end_row,
            start_col + X_0_Y_0_MULTIPLICATION_OFFSET,
        );
        self.fill_multiplication_trace_no_mod_reduction(
            &x[1],
            &y[1],
            start_row,
            end_row,
            start_col + X_1_Y_1_MULTIPLICATION_OFFSET,
        );

        let x0y0 =
            get_u32_vec_from_literal_24(BigUint::new(x[0].to_vec()) * BigUint::new(y[0].to_vec()));
        let modulus_sq = get_u32_vec_from_literal_24(modulus.clone() * modulus.clone());
        self.fill_addition_trace(&x0y0, &modulus_sq, start_row + 11, start_col + Z1_ADD_MODULUS_OFFSET);

        let x0y0_add_modsq =
            get_u32_vec_from_literal_24(BigUint::new(x0y0.to_vec()) + modulus.clone() * modulus);
        let x1y1 =
            get_u32_vec_from_literal_24(BigUint::new(x[1].to_vec()) * BigUint::new(y[1].to_vec()));
        self.fill_subtraction_trace(&x0y0_add_modsq, &x1y1, start_row + 11, start_col + Z1_SUBTRACTION_OFFSET);

        let x0y0_x1y1 = get_u32_vec_from_literal_24(
            BigUint::new(x0y0_add_modsq.to_vec()) - BigUint::new(x1y1.to_vec()),
        );
        let rem = self.fill_reduction_trace(&x0y0_x1y1, start_row, end_row, start_col + Z1_REDUCE_OFFSET);
        self.fill_range_check_trace(&rem, start_row, start_col + Z1_RANGECHECK_OFFSET);

        // filling trace for X0*Y1 + X1*Y0
        self.fill_multiplication_trace_no_mod_reduction(
            &x[0],
            &y[1],
            start_row,
            end_row,
            start_col + X_0_Y_1_MULTIPLICATION_OFFSET,
        );
        self.fill_multiplication_trace_no_mod_reduction(
            &x[1],
            &y[0],
            start_row,
            end_row,
            start_col + X_1_Y_0_MULTIPLICATION_OFFSET,
        );

        let x0y1 =
            get_u32_vec_from_literal_24(BigUint::new(x[0].to_vec()) * BigUint::new(y[1].to_vec()));
        let x1y0 =
            get_u32_vec_from_literal_24(BigUint::new(x[1].to_vec()) * BigUint::new(y[0].to_vec()));
        self.fill_addition_trace(&x0y1, &x1y0, start_row + 11, start_col + Z2_ADDITION_OFFSET);

        let x0y1_x1y0 =
            get_u32_vec_from_literal_24(BigUint::new(x0y1.to_vec()) + BigUint::new(x1y0.to_vec()));
        let rem = self.fill_reduction_trace(&x0y1_x1y0, start_row, end_row, start_col + Z2_REDUCE_OFFSET);
        self.fill_range_check_trace(&rem, start_row, start_col + Z2_RANGECHECK_OFFSET);
    }

    pub fn fill_trace_fp2_fp_mul(&mut self, x: &[[u32; 12]; 2], y: &[u32; 12], start_row: usize, end_row: usize, start_col: usize) {
        for i in start_row..end_row + 1 {
            self.trace[i][start_col + FP2_FP_MUL_SELECTOR_OFFSET] = F::ONE;
            self.assign_u32_in_series(i, start_col + FP2_FP_X_INPUT_OFFSET, &x[0]);
            self.assign_u32_in_series(i, start_col + FP2_FP_X_INPUT_OFFSET + 12, &x[1]);
            self.assign_u32_in_series(i, start_col + FP2_FP_Y_INPUT_OFFSET, y);
        }
        self.trace[end_row][start_col + FP2_FP_MUL_SELECTOR_OFFSET] = F::ZERO;
        self.fill_multiplication_trace_no_mod_reduction(&x[0], y, start_row, end_row, start_col + X0_Y_MULTIPLICATION_OFFSET);
        let x0y = get_u32_vec_from_literal_24(BigUint::new(x[0].to_vec()) * BigUint::new(y.to_vec()));
        let rem = self.fill_reduction_trace(&x0y, start_row, end_row, start_col + X0_Y_REDUCE_OFFSET);
        self.fill_range_check_trace(&rem, start_row, start_col + X0_Y_RANGECHECK_OFFSET);
        self.fill_multiplication_trace_no_mod_reduction(&x[1], y, start_row, end_row, start_col + X1_Y_MULTIPLICATION_OFFSET);
        let x1y = get_u32_vec_from_literal_24(BigUint::new(x[1].to_vec()) * BigUint::new(y.to_vec()));
        let rem = self.fill_reduction_trace(&x1y, start_row, end_row, start_col + X1_Y_REDUCE_OFFSET);
        self.fill_range_check_trace(&rem, start_row, start_col + X1_Y_RANGECHECK_OFFSET);
    }

    pub fn fill_trace_subtraction_with_reduction(&mut self, x: &[[u32; 12]; 2], y: &[[u32; 12]; 2], row: usize, start_col: usize) {
        let modulus = get_u32_vec_from_literal(modulus());
        self.fill_trace_addition_fp2(x, &[modulus, modulus], row, start_col);
        let x0_modulus = get_u32_vec_from_literal(
            BigUint::new(x[0].to_vec()) + BigUint::new(modulus.to_vec())
        );
        let x1_modulus = get_u32_vec_from_literal(
            BigUint::new(x[1].to_vec()) + BigUint::new(modulus.to_vec())
        );
        self.fill_trace_subtraction_fp2(&[x0_modulus, x1_modulus], y, row, start_col + FP2_ADDITION_TOTAL);
        let x0_y0 = get_u32_vec_from_literal(
            BigUint::new(x0_modulus.to_vec()) - BigUint::new(y[0].to_vec())
        );
        let x1_y1 = get_u32_vec_from_literal(
            BigUint::new(x1_modulus.to_vec()) - BigUint::new(y[1].to_vec())
        );
        let rem = self.fill_trace_reduce_single(&x0_y0, row, start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL);
        self.fill_range_check_trace(&rem, row, start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL);
        let rem = self.fill_trace_reduce_single(&x1_y1, row, start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL);
        self.fill_range_check_trace(&rem, row, start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL*2 + RANGE_CHECK_TOTAL);
    }

    pub fn fill_trace_addition_with_reduction(&mut self, x: &[[u32; 12]; 2], y: &[[u32; 12]; 2], row: usize, start_col: usize) {
        self.fill_trace_addition_fp2(x, y, row, start_col);
        let x0_y0 = get_u32_vec_from_literal(
            BigUint::new(x[0].to_vec()) + BigUint::new(y[0].to_vec())
        );
        let x1_y1 = get_u32_vec_from_literal(
            BigUint::new(x[1].to_vec()) + BigUint::new(y[1].to_vec())
        );
        let rem = self.fill_trace_reduce_single(&x0_y0, row, start_col + FP2_ADDITION_TOTAL);
        self.fill_range_check_trace(&rem, row, start_col + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL);
        let rem = self.fill_trace_reduce_single(&x1_y1, row, start_col + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL);
        self.fill_range_check_trace(&rem, row, start_col + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL*2 + RANGE_CHECK_TOTAL);
    }

    pub fn fill_trace_non_residue_multiplication(&mut self, x: &[[u32; 12]; 2], row: usize, start_col: usize) {
        self.trace[row][start_col + FP2_NON_RESIDUE_MUL_CHECK_OFFSET] = F::ONE;
        self.assign_u32_in_series(row, start_col + FP2_NON_RESIDUE_MUL_INPUT_OFFSET, &x.concat());
        self.fill_trace_addition_fp(&x[0], &get_u32_vec_from_literal(modulus()), row, start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET);
        let add_modulus = get_u32_vec_from_literal(
            BigUint::new(x[0].to_vec()) + modulus()
        );
        self.fill_trace_subtraction_fp(&add_modulus, &x[1], row, start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_TOTAL);
        let c0_c1_sub = get_u32_vec_from_literal(
            BigUint::new(add_modulus.to_vec()) - BigUint::new(x[1].to_vec())
        );
        let rem = self.fill_trace_reduce_single(&c0_c1_sub, row, start_col + FP2_NON_RESIDUE_MUL_Z0_REDUCE_OFFSET);
        self.fill_range_check_trace(&rem, row, start_col + FP2_NON_RESIDUE_MUL_Z0_RANGECHECK_OFFSET);
        self.fill_trace_addition_fp(&x[0], &x[1], row, start_col + FP2_NON_RESIDUE_MUL_C0_C1_ADD_OFFSET);
        let c0_c1_add = get_u32_vec_from_literal(
            BigUint::new(x[0].to_vec()) + BigUint::new(x[1].to_vec())
        );
        let rem = self.fill_trace_reduce_single(&c0_c1_add, row, start_col + FP2_NON_RESIDUE_MUL_Z1_REDUCE_OFFSET);
        self.fill_range_check_trace(&rem, row, start_col + FP2_NON_RESIDUE_MUL_Z1_RANGECHECK_OFFSET);
    }

    pub fn fill_trace_addition_fp6(&mut self, x: &[[u32; 12]; 6], y: &[[u32; 12]; 6], row: usize, start_col: usize) {
        self.fill_trace_addition_fp2(&[x[0], x[1]], &[y[0], y[1]], row, start_col + FP6_ADDITION_0_OFFSET);
        self.fill_trace_addition_fp2(&[x[2], x[3]], &[y[2], y[3]], row, start_col + FP6_ADDITION_1_OFFSET);
        self.fill_trace_addition_fp2(&[x[4], x[5]], &[y[4], y[5]], row, start_col + FP6_ADDITION_2_OFFSET);
    }

    pub fn fill_trace_addition_with_reduction_fp6(&mut self, x: &Fp6, y: &Fp6, row: usize, start_col: usize) {
        self.fill_trace_addition_fp6(&x.get_u32_slice(), &y.get_u32_slice(), row, start_col);
        for i in 0..6 {
            let sum = get_u32_vec_from_literal(
                BigUint::new(x.0[i].0.to_vec()) + BigUint::new(y.0[i].0.to_vec())
            );
            let rem = self.fill_trace_reduce_single(&sum, row, start_col + FP6_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*i);
            self.fill_range_check_trace(&rem, row, start_col + FP6_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*i + FP_SINGLE_REDUCE_TOTAL);
        }
    }

    pub fn fill_trace_subtraction_with_reduction_fp6(&mut self, x: &Fp6, y: &Fp6, row: usize, start_col: usize) {
        let modulus = vec![get_u32_vec_from_literal(modulus()); 6].try_into().unwrap();
        self.fill_trace_addition_fp6(&x.get_u32_slice(), &modulus, row, start_col);
        let x_modulus = modulus
            .iter()
            .zip(x.get_u32_slice())
            .map(|(m, f)| get_u32_vec_from_literal(
                BigUint::new(m.to_vec()) + BigUint::new(f.to_vec())
            ))
            .collect::<Vec<[u32; 12]>>()
            .try_into()
            .unwrap();
        self.fill_trace_subtraction_fp6(&x_modulus, &y.get_u32_slice(), row, start_col + FP6_ADDITION_TOTAL);
        for i in 0..6 {
            let diff = get_u32_vec_from_literal(
                BigUint::new(x_modulus[i].to_vec()) - BigUint::new(y.0[i].0.to_vec())
            );
            let rem = self.fill_trace_reduce_single(&diff, row, start_col + FP6_ADDITION_TOTAL + FP6_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*i);
            self.fill_range_check_trace(&rem, row, start_col + FP6_ADDITION_TOTAL + FP6_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*i + FP_SINGLE_REDUCE_TOTAL);
        }
    }

    pub fn fill_trace_subtraction_fp6(&mut self, x: &[[u32; 12]; 6], y: &[[u32; 12]; 6], row: usize, start_col: usize) {
        self.fill_trace_subtraction_fp2(&[x[0], x[1]], &[y[0], y[1]], row, start_col + FP6_SUBTRACTION_0_OFFSET);
        self.fill_trace_subtraction_fp2(&[x[2], x[3]], &[y[2], y[3]], row, start_col + FP6_SUBTRACTION_1_OFFSET);
        self.fill_trace_subtraction_fp2(&[x[4], x[5]], &[y[4], y[5]], row, start_col + FP6_SUBTRACTION_2_OFFSET);
    }

    pub fn fill_trace_negate_fp6(
        &mut self,
        x: &Fp6,
        row: usize,
        start_col: usize
    ) {
        self.fill_trace_addition_fp6(&x.get_u32_slice(), &(-(*x)).get_u32_slice(), row, start_col);
    }

    pub fn fill_trace_non_residue_multiplication_fp6(&mut self, x: &Fp6, row: usize, start_col: usize) {
        self.trace[row][start_col + FP6_NON_RESIDUE_MUL_CHECK_OFFSET] = F::ONE;
        for (i, e) in x.0.iter().enumerate() {
            self.assign_u32_in_series(row, start_col + FP6_NON_RESIDUE_MUL_INPUT_OFFSET + i*12, &e.0);
        }
        let c2 = Fp2([x.0[4], x.0[5]]);
        self.fill_trace_non_residue_multiplication(&c2.get_u32_slice(), row, start_col + FP6_NON_RESIDUE_MUL_C2);
    }

    pub fn fill_trace_fp6_multiplication(&mut self, x: &Fp6, y: &Fp6, start_row: usize, end_row: usize, start_col: usize) {
        for i in 0..6 {
            for row in start_row..end_row+1 {
                self.assign_u32_in_series(row, start_col + FP6_MUL_X_INPUT_OFFSET + 12*i, &x.0[i].0);
                self.assign_u32_in_series(row, start_col + FP6_MUL_Y_INPUT_OFFSET + 12*i, &y.0[i].0);
                self.trace[row][start_col + FP6_MUL_SELECTOR_OFFSET] = F::ONE;
            }
        }
        self.trace[end_row][start_col + FP6_MUL_SELECTOR_OFFSET] = F::ZERO;
        let (c0, c1, c2) = (Fp2([x.0[0], x.0[1]]), Fp2([x.0[2], x.0[3]]), Fp2([x.0[4], x.0[5]]));
        let (r0, r1, r2) = (Fp2([y.0[0], y.0[1]]), Fp2([y.0[2], y.0[3]]), Fp2([y.0[4], y.0[5]]));
        
        let t0 = c0*r0;
        self.generate_trace_fp2_mul(c0.get_u32_slice(), r0.get_u32_slice(), start_row, end_row, start_col + FP6_MUL_T0_CALC_OFFSET);
        let t1 = c1*r1;
        self.generate_trace_fp2_mul(c1.get_u32_slice(), r1.get_u32_slice(), start_row, end_row, start_col + FP6_MUL_T1_CALC_OFFSET);
        let t2 = c2*r2;
        self.generate_trace_fp2_mul(c2.get_u32_slice(), r2.get_u32_slice(), start_row, end_row, start_col + FP6_MUL_T2_CALC_OFFSET);

        let t3 = c1+c2;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction(&c1.get_u32_slice(), &c2.get_u32_slice(), row, start_col + FP6_MUL_T3_CALC_OFFSET);
        }
        let t4 = r1+r2;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction(&r1.get_u32_slice(), &r2.get_u32_slice(), row, start_col + FP6_MUL_T4_CALC_OFFSET);
        }
        let t5 = t3*t4;
        self.generate_trace_fp2_mul(t3.get_u32_slice(), t4.get_u32_slice(), start_row, end_row, start_col + FP6_MUL_T5_CALC_OFFSET);
        let t6 = t5-t1;
        for row in start_row..end_row+1 {
            self.fill_trace_subtraction_with_reduction(&t5.get_u32_slice(), &t1.get_u32_slice(), row, start_col + FP6_MUL_T6_CALC_OFFSET);
        }
        let t7 = t6-t2;
        for row in start_row..end_row+1 {
            self.fill_trace_subtraction_with_reduction(&t6.get_u32_slice(), &t2.get_u32_slice(), row, start_col + FP6_MUL_T7_CALC_OFFSET);
        }
        let t8 = t7.mul_by_nonresidue();
        for row in start_row..end_row+1 {
            self.fill_trace_non_residue_multiplication(&t7.get_u32_slice(), row, start_col + FP6_MUL_T8_CALC_OFFSET);
        }
        let _x = t8+t0;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction(&t8.get_u32_slice(), &t0.get_u32_slice(), row, start_col + FP6_MUL_X_CALC_OFFSET);
        }

        let t9 = c0+c1;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction(&c0.get_u32_slice(), &c1.get_u32_slice(), row, start_col + FP6_MUL_T9_CALC_OFFSET);
        }
        let t10 = r0+r1;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction(&r0.get_u32_slice(), &r1.get_u32_slice(), row, start_col + FP6_MUL_T10_CALC_OFFSET);
        }
        let t11 = t9*t10;
        self.generate_trace_fp2_mul(t9.get_u32_slice(), t10.get_u32_slice(), start_row, end_row, start_col + FP6_MUL_T11_CALC_OFFSET);
        let t12 = t11-t0;
        for row in start_row..end_row+1 {
            self.fill_trace_subtraction_with_reduction(&t11.get_u32_slice(), &t0.get_u32_slice(), row, start_col + FP6_MUL_T12_CALC_OFFSET);
        }
        let t13 = t12-t1;
        for row in start_row..end_row+1 {
            self.fill_trace_subtraction_with_reduction(&t12.get_u32_slice(), &t1.get_u32_slice(), row, start_col + FP6_MUL_T13_CALC_OFFSET);
        }
        let t14 = t2.mul_by_nonresidue();
        for row in start_row..end_row+1 {
            self.fill_trace_non_residue_multiplication(&t2.get_u32_slice(), row, start_col + FP6_MUL_T14_CALC_OFFSET);
        }
        let _y = t13+t14;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction(&t13.get_u32_slice(), &t14.get_u32_slice(), row, start_col + FP6_MUL_Y_CALC_OFFSET);
        }

        let t15 = c0+c2;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction(&c0.get_u32_slice(), &c2.get_u32_slice(), row, start_col + FP6_MUL_T15_CALC_OFFSET);
        }
        let t16 = r0+r2;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction(&r0.get_u32_slice(), &r2.get_u32_slice(), row, start_col + FP6_MUL_T16_CALC_OFFSET);
        }
        let t17 = t15*t16;
        self.generate_trace_fp2_mul(t15.get_u32_slice(), t16.get_u32_slice(), start_row, end_row, start_col + FP6_MUL_T17_CALC_OFFSET);
        let t18 = t17-t0;
        for row in start_row..end_row+1 {
            self.fill_trace_subtraction_with_reduction(&t17.get_u32_slice(), &t0.get_u32_slice(), row, start_col + FP6_MUL_T18_CALC_OFFSET);
        }
        let t19 = t18-t2;
        for row in start_row..end_row+1 {
            self.fill_trace_subtraction_with_reduction(&t18.get_u32_slice(), &t2.get_u32_slice(), row, start_col + FP6_MUL_T19_CALC_OFFSET);
        }
        let _z = t19+t1;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction(&t19.get_u32_slice(), &t1.get_u32_slice(), row, start_col + FP6_MUL_Z_CALC_OFFSET);
        }
    }

    pub fn fill_trace_fp12_multiplication(&mut self, x: &Fp12, y: &Fp12, start_row: usize, end_row: usize, start_col: usize) {
        for row in start_row..end_row+1 {
            for i in 0..12 {
                self.assign_u32_in_series(row, start_col + FP12_MUL_X_INPUT_OFFSET + i*12, &x.0[i].0);
                self.assign_u32_in_series(row, start_col + FP12_MUL_Y_INPUT_OFFSET + i*12, &y.0[i].0);
            }
            self.trace[row][start_col + FP12_MUL_SELECTOR_OFFSET] = F::ONE;
        }
        self.trace[end_row][start_col + FP12_MUL_SELECTOR_OFFSET] = F::ZERO;
        let (c0, c1) = (Fp6(x.0[0..6].try_into().unwrap()), Fp6(x.0[6..12].try_into().unwrap()));
        let (r0, r1) = (Fp6(y.0[0..6].try_into().unwrap()), Fp6(y.0[6..12].try_into().unwrap()));
        let t0 = c0*r0;
        self.fill_trace_fp6_multiplication(&c0, &r0, start_row, end_row, start_col + FP12_MUL_T0_CALC_OFFSET);
        let t1 = c1*r1;
        self.fill_trace_fp6_multiplication(&c1, &r1, start_row, end_row, start_col + FP12_MUL_T1_CALC_OFFSET);
        let t2 = mul_by_nonresidue(t1.0);
        for row in start_row..end_row+1 {
            self.fill_trace_non_residue_multiplication_fp6(&t1, row, start_col + FP12_MUL_T2_CALC_OFFSET);
        }
        let _x = t0+t2;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction_fp6(&t0, &t2, row, start_col + FP12_MUL_X_CALC_OFFSET);
        }

        let t3 = c0+c1;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction_fp6(&c0, &c1, row, start_col + FP12_MUL_T3_CALC_OFFSET);
        }
        let t4 = r0+r1;
        for row in start_row..end_row+1 {
            self.fill_trace_addition_with_reduction_fp6(&r0, &r1, row, start_col + FP12_MUL_T4_CALC_OFFSET);
        }
        let t5 = t3*t4;
        self.fill_trace_fp6_multiplication(&t3, &t4, start_row, end_row, start_col + FP12_MUL_T5_CALC_OFFSET);
        let t6 = t5-t0;
        for row in start_row..end_row+1 {
            self.fill_trace_subtraction_with_reduction_fp6(&t5, &t0, row, start_col + FP12_MUL_T6_CALC_OFFSET);
        }
        let _y = t6-t1;
        for row in start_row..end_row+1 {
            self.fill_trace_subtraction_with_reduction_fp6(&t6, &t1, row, start_col + FP12_MUL_Y_CALC_OFFSET);
        }
    }

    pub fn fill_trace_fp2_forbenius_map(&mut self, x: &Fp2, pow: usize, start_row: usize, end_row: usize, start_col: usize) {
        let div = pow / 2;
        let rem = pow % 2;
        for row in start_row..end_row + 1 {
            self.assign_u32_in_series(row, start_col + FP2_FORBENIUS_MAP_INPUT_OFFSET, &x.get_u32_slice().concat());
            self.trace[row][start_col + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] = F::ONE;
            self.trace[row][start_col + FP2_FORBENIUS_MAP_POW_OFFSET] = F::from_canonical_usize(pow);
            self.trace[row][start_col + FP2_FORBENIUS_MAP_DIV_OFFSET] = F::from_canonical_usize(div);
            self.trace[row][start_col + FP2_FORBENIUS_MAP_REM_OFFSET] = F::from_canonical_usize(rem);
            self.trace[row][start_col + FP2_FORBENIUS_MAP_ROW_NUM] = F::from_canonical_usize(row);
        }
        self.trace[end_row][start_col + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] = F::ZERO;
        let forbenius_coefficients = Fp2::forbenius_coefficients();
        self.fill_multiplication_trace_no_mod_reduction(&x.0[1].0, &forbenius_coefficients[rem].0, start_row, end_row, start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET);
        self.trace[start_row + 11][start_col + FP2_FORBENIUS_MAP_MUL_RES_ROW] = F::ONE;
        let x_y = get_u32_vec_from_literal_24(x.0[1].to_biguint() * forbenius_coefficients[rem].to_biguint());
        let res = self.fill_reduction_trace(&x_y, start_row, end_row, start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS);
        for row in start_row..end_row + 1 {
            self.fill_range_check_trace(&res, row, start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS + REDUCTION_TOTAL);
        }
        let res = Fp2([x.0[0], Fp(res)]);
        assert_eq!(res, x.forbenius_map(pow));
    }

    pub fn fill_trace_fp6_forbenius_map(&mut self, x: &Fp6, pow: usize, start_row: usize, end_row: usize, start_col: usize) {
        let div = pow / 6;
        let rem = pow % 6;
        for row in start_row..end_row + 1 {
            self.assign_u32_in_series(row, start_col + FP6_FORBENIUS_MAP_INPUT_OFFSET, &x.get_u32_slice().concat());
            self.trace[row][start_col + FP6_FORBENIUS_MAP_SELECTOR_OFFSET] = F::ONE;
            self.trace[row][start_col + FP6_FORBENIUS_MAP_POW_OFFSET] = F::from_canonical_usize(pow);
            self.trace[row][start_col + FP6_FORBENIUS_MAP_DIV_OFFSET] = F::from_canonical_usize(div);
            self.trace[row][start_col + FP6_FORBENIUS_MAP_REM_OFFSET] = F::from_canonical_usize(rem);
            self.trace[row][start_col + FP6_FORBENIUS_MAP_BIT0_OFFSET] = F::from_canonical_usize(rem&1);
            self.trace[row][start_col + FP6_FORBENIUS_MAP_BIT1_OFFSET] = F::from_canonical_usize((rem>>1)&1);
            self.trace[row][start_col + FP6_FORBENIUS_MAP_BIT2_OFFSET] = F::from_canonical_usize(rem>>2);
        }
        self.trace[end_row][start_col + FP6_FORBENIUS_MAP_SELECTOR_OFFSET] = F::ZERO;
        let c0 = Fp2(x.0[0..2].to_vec().try_into().unwrap());
        let c1 = Fp2(x.0[2..4].to_vec().try_into().unwrap());
        let c2 = Fp2(x.0[4..6].to_vec().try_into().unwrap());
        let forbenius_coefficients_1 = Fp6::forbenius_coefficients_1();
        let forbenius_coefficients_2 = Fp6::forbenius_coefficients_2();
        let _x = c0.forbenius_map(pow);
        self.fill_trace_fp2_forbenius_map(&c0, pow, start_row, end_row, start_col + FP6_FORBENIUS_MAP_X_CALC_OFFSET);
        let t0 = c1.forbenius_map(pow);
        self.fill_trace_fp2_forbenius_map(&c1, pow, start_row, end_row, start_col + FP6_FORBENIUS_MAP_T0_CALC_OFFSET);
        let _y = t0 * forbenius_coefficients_1[pow%6];
        self.generate_trace_fp2_mul(t0.get_u32_slice(), forbenius_coefficients_1[pow%6].get_u32_slice(), start_row, end_row, start_col + FP6_FORBENIUS_MAP_Y_CALC_OFFSET);
        let t1 = c2.forbenius_map(pow);
        self.fill_trace_fp2_forbenius_map(&c2, pow, start_row, end_row, start_col + FP6_FORBENIUS_MAP_T1_CALC_OFFSET);
        let _z = t1 * forbenius_coefficients_2[pow%6];
        self.generate_trace_fp2_mul(t1.get_u32_slice(), forbenius_coefficients_2[pow%6].get_u32_slice(), start_row, end_row, start_col + FP6_FORBENIUS_MAP_Z_CALC_OFFSET);
    }

    pub fn fill_trace_fp12_forbenius_map(&mut self, x: &Fp12, pow: usize, start_row: usize, end_row: usize, start_col: usize) {
        let div = pow / 12;
        let rem = pow % 12;
        for row in start_row..end_row + 1 {
            self.assign_u32_in_series(row, start_col + FP12_FORBENIUS_MAP_INPUT_OFFSET, &x.get_u32_slice().concat());
            self.trace[row][start_col + FP12_FORBENIUS_MAP_SELECTOR_OFFSET] = F::ONE;
            self.trace[row][start_col + FP12_FORBENIUS_MAP_POW_OFFSET] = F::from_canonical_usize(pow);
            self.trace[row][start_col + FP12_FORBENIUS_MAP_DIV_OFFSET] = F::from_canonical_usize(div);
            self.trace[row][start_col + FP12_FORBENIUS_MAP_REM_OFFSET] = F::from_canonical_usize(rem);
            self.trace[row][start_col + FP12_FORBENIUS_MAP_BIT0_OFFSET] = F::from_canonical_usize(rem&1);
            self.trace[row][start_col + FP12_FORBENIUS_MAP_BIT1_OFFSET] = F::from_canonical_usize((rem>>1)&1);
            self.trace[row][start_col + FP12_FORBENIUS_MAP_BIT2_OFFSET] = F::from_canonical_usize((rem>>2)&1);
            self.trace[row][start_col + FP12_FORBENIUS_MAP_BIT3_OFFSET] = F::from_canonical_usize(rem>>3);
        }
        let r0 = Fp6(x.0[0..6].to_vec().try_into().unwrap());
        let r1 = Fp6(x.0[6..12].to_vec().try_into().unwrap());
        let _x = r0.forbenius_map(pow);
        self.fill_trace_fp6_forbenius_map(&r0, pow, start_row, end_row, start_col + FP12_FORBENIUS_MAP_R0_CALC_OFFSET);
        let c0c1c2 = r1.forbenius_map(pow);
        self.fill_trace_fp6_forbenius_map(&r1, pow, start_row, end_row, start_col + FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET);
        let c0 = Fp2(c0c1c2.0[0..2].to_vec().try_into().unwrap());
        let c1 = Fp2(c0c1c2.0[2..4].to_vec().try_into().unwrap());
        let c2 = Fp2(c0c1c2.0[4..6].to_vec().try_into().unwrap());
        let forbenius_coefficients = Fp12::forbenius_coefficients();
        let coeff = forbenius_coefficients[pow % 12];
        self.generate_trace_fp2_mul(c0.get_u32_slice(), coeff.get_u32_slice(), start_row, end_row, start_col + FP12_FORBENIUS_MAP_C0_CALC_OFFSET);
        self.generate_trace_fp2_mul(c1.get_u32_slice(), coeff.get_u32_slice(), start_row, end_row, start_col + FP12_FORBENIUS_MAP_C1_CALC_OFFSET);
        self.generate_trace_fp2_mul(c2.get_u32_slice(), coeff.get_u32_slice(), start_row, end_row, start_col + FP12_FORBENIUS_MAP_C2_CALC_OFFSET);
    }

    pub fn generate_trace(&mut self, x: Fp12, pow: usize) {
        self.fill_trace_fp12_forbenius_map(&x, pow, 0, self.num_rows-1, 0);

    }
}

pub fn trace_rows_to_poly_values<F: Field>(
    trace_rows: Vec<[F; TOTAL_COLUMNS]>,
) -> Vec<PolynomialValues<F>> {
    let trace_row_vecs = trace_rows.into_iter().map(|row| row.to_vec()).collect_vec();
    let trace_col_vecs: Vec<Vec<F>> = transpose(&trace_row_vecs);
    trace_col_vecs
        .into_iter()
        .map(|column| PolynomialValues::new(column))
        .collect()
}

pub fn add_multiplication_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    next_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    // Constrains the X and Y is filled same across the rows
    for i in 0..12 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + MULTIPLICATION_SELECTOR_OFFSET] *
            (
                local_values[start_col + X_INPUT_OFFSET + i]
                - next_values[start_col + X_INPUT_OFFSET + i]
            ),
        );
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + MULTIPLICATION_SELECTOR_OFFSET] *
            (
                local_values[start_col + Y_INPUT_OFFSET + i]
                - next_values[start_col + Y_INPUT_OFFSET + i]
            ),
        );
    }

    // Constrain that multiplication happens correctly at each level
    for i in 0..12 {
        for j in 0..12 {
            if j == 0 {
                yield_constr.constraint_transition(
                    //local_values[start_col + MULTIPLICATION_SELECTOR_OFFSET] *
                    bit_selector.unwrap_or(P::ONES) *
                    local_values[start_col + SELECTOR_OFFSET + i]
                        * (local_values[start_col + X_INPUT_OFFSET + j]
                            * local_values[start_col + Y_INPUT_OFFSET + i]
                            - local_values[start_col + XY_OFFSET + j]
                            - (local_values[start_col + XY_CARRIES_OFFSET + j]
                                * FE::from_canonical_u64(1 << 32))),
                )
            } else {
                yield_constr.constraint_transition(
                    //local_values[start_col + MULTIPLICATION_SELECTOR_OFFSET] *
                    bit_selector.unwrap_or(P::ONES) *
                    local_values[start_col + SELECTOR_OFFSET + i]
                        * (local_values[start_col + X_INPUT_OFFSET + j]
                            * local_values[start_col + Y_INPUT_OFFSET + i]
                            + local_values[start_col + XY_CARRIES_OFFSET + j - 1]
                            - local_values[start_col + XY_OFFSET + j]
                            - (local_values[start_col + XY_CARRIES_OFFSET + j]
                                * FE::from_canonical_u64(1 << 32))),
                )
            }
        }
    }
    yield_constr.constraint_transition(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + MULTIPLICATION_SELECTOR_OFFSET]
            * (local_values[start_col + XY_OFFSET + 12]
                - local_values[start_col + XY_CARRIES_OFFSET + 11]),
    );

    // Constrain XY SHIFTING
    for i in 0..12 {
        // shift is decided by selector
        for j in 0..13 {
            yield_constr.constraint_transition(
                //local_values[start_col + MULTIPLICATION_SELECTOR_OFFSET] *
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + SELECTOR_OFFSET + i]
                    * (local_values[start_col + SHIFTED_XY_OFFSET + j + i]
                        - local_values[start_col + XY_OFFSET + j]),
            )
        }
    }

    // Constrain addition at each row
    // 1. Constrain XY_SUM at row 0 is same as XY_SHIFTED
    // 2. Constrain XY_SUM_CARRIES at row 0 are all 0
    for j in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + MULTIPLICATION_FIRST_ROW_OFFSET] *
            (
            local_values[start_col + SUM_OFFSET + j]
                - local_values[start_col + SHIFTED_XY_OFFSET + j]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + MULTIPLICATION_FIRST_ROW_OFFSET] *
            local_values[start_col + SUM_CARRIES_OFFSET + j],
        )
    }
    // yield_constr.constraint_first_row(//local_values[start_col + MULTIPLICATION_SELECTOR_OFFSET] *
    //     local_values[start_col + SUM_OFFSET + 24]);

    // 3. Constrain addition
    yield_constr.constraint_transition(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + MULTIPLICATION_SELECTOR_OFFSET]
            * (next_values[start_col + SUM_OFFSET]
                + (next_values[start_col + SUM_CARRIES_OFFSET] * FE::from_canonical_u64(1 << 32))
                - next_values[start_col + SHIFTED_XY_OFFSET]
                - local_values[start_col + SUM_OFFSET]),
    );

    for j in 1..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + MULTIPLICATION_SELECTOR_OFFSET]
                * (next_values[start_col + SUM_OFFSET + j]
                    + (next_values[start_col + SUM_CARRIES_OFFSET + j]
                        * FE::from_canonical_u64(1 << 32))
                    - next_values[start_col + SHIFTED_XY_OFFSET + j]
                    - local_values[start_col + SUM_OFFSET + j]
                    - next_values[start_col + SUM_CARRIES_OFFSET + j - 1]),
        )
    }
    // yield_constr.constraint_transition(local_values[start_col + MULTIPLICATION_SELECTOR_OFFSET] * (next_values[start_col + SUM_OFFSET + 24] - next_values[start_col + SUM_CARRIES_OFFSET + 23]));
}

pub fn add_addition_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for j in 0..24 {
        if j == 0 {
            yield_constr.constraint_transition(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + ADDITION_CHECK_OFFSET]
                    * (local_values[start_col + ADDITION_SUM_OFFSET + j]
                        + (local_values[start_col + ADDITION_CARRY_OFFSET + j]
                            * FE::from_canonical_u64(1 << 32))
                        - local_values[start_col + ADDITION_X_OFFSET + j]
                        - local_values[start_col + ADDITION_Y_OFFSET + j]),
            )
        } else {
            yield_constr.constraint_transition(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + ADDITION_CHECK_OFFSET]
                    * (local_values[start_col + ADDITION_SUM_OFFSET + j]
                        + (local_values[start_col + ADDITION_CARRY_OFFSET + j]
                            * FE::from_canonical_u64(1 << 32))
                        - local_values[start_col + ADDITION_X_OFFSET + j]
                        - local_values[start_col + ADDITION_Y_OFFSET + j]
                        - local_values[start_col + ADDITION_CARRY_OFFSET + j - 1]),
            )
        }
    }
}

pub fn add_addition_fp_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for j in 0..12 {
        if j == 0 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP_ADDITION_CHECK_OFFSET]
                    * (local_values[start_col + FP_ADDITION_SUM_OFFSET + j]
                        + (local_values[start_col + FP_ADDITION_CARRY_OFFSET + j]
                            * FE::from_canonical_u64(1 << 32))
                        - local_values[start_col + FP_ADDITION_X_OFFSET + j]
                        - local_values[start_col + FP_ADDITION_Y_OFFSET + j]),
            )
        } else {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP_ADDITION_CHECK_OFFSET]
                    * (local_values[start_col + FP_ADDITION_SUM_OFFSET + j]
                        + (local_values[start_col + FP_ADDITION_CARRY_OFFSET + j]
                            * FE::from_canonical_u64(1 << 32))
                        - local_values[start_col + FP_ADDITION_X_OFFSET + j]
                        - local_values[start_col + FP_ADDITION_Y_OFFSET + j]
                        - local_values[start_col + FP_ADDITION_CARRY_OFFSET + j - 1]),
            )
        }
    }
}

pub fn add_subtraction_fp_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for j in 0..12 {
        if j == 0 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP_SUBTRACTION_CHECK_OFFSET]
                    * (local_values[start_col + FP_SUBTRACTION_DIFF_OFFSET + j]
                        + local_values[start_col + FP_SUBTRACTION_Y_OFFSET + j]
                        - (local_values[start_col + FP_SUBTRACTION_BORROW_OFFSET + j]
                            * FE::from_canonical_u64(1 << 32))
                        - local_values[start_col + FP_SUBTRACTION_X_OFFSET + j]),
            )
        } else {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP_SUBTRACTION_CHECK_OFFSET]
                    * (local_values[start_col + FP_SUBTRACTION_DIFF_OFFSET + j]
                        + local_values[start_col + FP_SUBTRACTION_Y_OFFSET + j]
                        + local_values[start_col + FP_SUBTRACTION_BORROW_OFFSET + j - 1]
                        - (local_values[start_col + FP_SUBTRACTION_BORROW_OFFSET + j]
                            * FE::from_canonical_u64(1 << 32))
                        - local_values[start_col + FP_SUBTRACTION_X_OFFSET + j]),
            )
        }
    }
}

pub fn add_negate_fp_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_addition_fp_constraints(local_values, yield_constr, start_col, bit_selector);
    let mod_u32 = get_u32_vec_from_literal(modulus());
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP_ADDITION_SUM_OFFSET + i] - FE::from_canonical_u32(mod_u32[i])
            )
        );
    }
}

pub fn add_fp_single_multiply_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for j in 0..12 {
        if j == 0 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP_MULTIPLY_SINGLE_CHECK_OFFSET] *
                (local_values[start_col + FP_MULTIPLY_SINGLE_SUM_OFFSET + j]
                    + (local_values[start_col + FP_MULTIPLY_SINGLE_CARRY_OFFSET + j]
                        * FE::from_canonical_u64(1 << 32))
                    - local_values[start_col + FP_MULTIPLY_SINGLE_X_OFFSET + j]
                    * local_values[start_col + FP_MULTIPLY_SINGLE_Y_OFFSET]),
            )
        } else {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP_MULTIPLY_SINGLE_CHECK_OFFSET] *
                (local_values[start_col + FP_MULTIPLY_SINGLE_SUM_OFFSET + j]
                    + (local_values[start_col + FP_MULTIPLY_SINGLE_CARRY_OFFSET + j]
                        * FE::from_canonical_u64(1 << 32))
                    - local_values[start_col + FP_MULTIPLY_SINGLE_X_OFFSET + j]
                    * local_values[start_col + FP_MULTIPLY_SINGLE_Y_OFFSET]
                    - local_values[start_col + FP_MULTIPLY_SINGLE_CARRY_OFFSET + j - 1]),
            )
        }
    }
}

pub fn add_fp_reduce_single_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    let modulus = modulus();
    let modulus_u32 = get_u32_vec_from_literal(modulus);
    for i in 0..12 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP_SINGLE_REDUCE_MULTIPLICATION_OFFSET + FP_MULTIPLY_SINGLE_CHECK_OFFSET] * (
                local_values[start_col + FP_SINGLE_REDUCE_MULTIPLICATION_OFFSET + FP_MULTIPLY_SINGLE_X_OFFSET + i] -
                FE::from_canonical_u32(modulus_u32[i])
            )
        );
    }

    add_fp_single_multiply_constraints(local_values, yield_constr, start_col + FP_SINGLE_REDUCE_MULTIPLICATION_OFFSET, bit_selector);

    for i in 0..12 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP_SINGLE_REDUCTION_ADDITION_OFFSET + FP_ADDITION_CHECK_OFFSET]
                * (local_values[start_col + FP_SINGLE_REDUCE_MULTIPLICATION_OFFSET + FP_MULTIPLY_SINGLE_SUM_OFFSET + i]
                    - local_values[start_col + FP_SINGLE_REDUCTION_ADDITION_OFFSET + FP_ADDITION_X_OFFSET + i]),
        );
    }

    add_addition_fp_constraints(
        local_values,
        yield_constr,
        start_col + FP_SINGLE_REDUCTION_ADDITION_OFFSET,
        bit_selector,
    );

    for i in 0..12 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP_SINGLE_REDUCTION_ADDITION_OFFSET + FP_ADDITION_CHECK_OFFSET]
                * (local_values[start_col + FP_SINGLE_REDUCED_OFFSET + i]
                    - local_values
                        [start_col + FP_SINGLE_REDUCTION_ADDITION_OFFSET + FP_ADDITION_Y_OFFSET + i]),
        );
    }

    for i in 0..12 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP_SINGLE_REDUCTION_ADDITION_OFFSET + FP_ADDITION_CHECK_OFFSET]
                * (local_values[start_col + FP_SINGLE_REDUCE_X_OFFSET + i]
                    - local_values
                        [start_col + FP_SINGLE_REDUCTION_ADDITION_OFFSET + FP_ADDITION_SUM_OFFSET + i]),
        )
    }

}

pub fn add_addition_fp2_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_addition_fp_constraints(local_values, yield_constr, start_col + FP2_ADDITION_0_OFFSET, bit_selector);
    add_addition_fp_constraints(local_values, yield_constr, start_col + FP2_ADDITION_1_OFFSET, bit_selector);
}

pub fn add_subtraction_fp2_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_subtraction_fp_constraints(local_values, yield_constr, start_col + FP2_SUBTRACTION_0_OFFSET, bit_selector);
    add_subtraction_fp_constraints(local_values, yield_constr, start_col + FP2_SUBTRACTION_1_OFFSET, bit_selector);
}

pub fn add_fp2_single_multiply_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_fp_single_multiply_constraints(local_values, yield_constr, start_col + FP2_MULTIPLY_SINGLE_0_OFFSET, bit_selector);
    add_fp_single_multiply_constraints(local_values, yield_constr, start_col + FP2_MULTIPLY_SINGLE_1_OFFSET, bit_selector);
}

pub fn add_negate_fp2_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_addition_fp2_constraints(local_values, yield_constr, start_col, bit_selector);
    let mod_u32 = get_u32_vec_from_literal(modulus());
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP2_ADDITION_0_OFFSET + FP_ADDITION_SUM_OFFSET + i] - FE::from_canonical_u32(mod_u32[i])
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP2_ADDITION_1_OFFSET + FP_ADDITION_SUM_OFFSET + i] - FE::from_canonical_u32(mod_u32[i])
            )
        );
    }
}

pub fn add_subtraction_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for j in 0..24 {
        if j == 0 {
            yield_constr.constraint_transition(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + SUBTRACTION_CHECK_OFFSET]
                    * (local_values[start_col + SUBTRACTION_DIFF_OFFSET + j]
                        + local_values[start_col + SUBTRACTION_Y_OFFSET + j]
                        - (local_values[start_col + SUBTRACTION_BORROW_OFFSET + j]
                            * FE::from_canonical_u64(1 << 32))
                        - local_values[start_col + SUBTRACTION_X_OFFSET + j]),
            )
        } else {
            yield_constr.constraint_transition(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + SUBTRACTION_CHECK_OFFSET]
                    * (local_values[start_col + SUBTRACTION_DIFF_OFFSET + j]
                        + local_values[start_col + SUBTRACTION_Y_OFFSET + j]
                        + local_values[start_col + SUBTRACTION_BORROW_OFFSET + j - 1]
                        - (local_values[start_col + SUBTRACTION_BORROW_OFFSET + j]
                            * FE::from_canonical_u64(1 << 32))
                        - local_values[start_col + SUBTRACTION_X_OFFSET + j]),
            )
        }
    }
}

pub fn add_range_check_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    let y = (BigUint::from(1u32) << 382) - modulus();
    let y_u32 = get_u32_vec_from_literal(y);

    for i in 0..12 {
        if i == 0 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + RANGE_CHECK_SELECTOR_OFFSET] * (
                    local_values[start_col + RANGE_CHECK_SUM_OFFSET + i]
                        + (local_values[start_col + RANGE_CHECK_SUM_CARRY_OFFSET + i]
                            * FE::from_canonical_u64(1 << 32))
                        - FE::from_canonical_u32(y_u32[i])
                        - local_values[start_col - 12 + i]
                )
            );
        } else if i < 12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + RANGE_CHECK_SELECTOR_OFFSET] * (
                    local_values[start_col + RANGE_CHECK_SUM_OFFSET + i]
                        + (local_values[start_col + RANGE_CHECK_SUM_CARRY_OFFSET + i]
                            * FE::from_canonical_u64(1 << 32))
                        - FE::from_canonical_u32(y_u32[i])
                        - local_values[start_col - 12 + i]
                        - local_values[start_col + RANGE_CHECK_SUM_CARRY_OFFSET + i - 1]
                )
            );
        }
        let bit_col: usize = start_col + RANGE_CHECK_BIT_DECOMP_OFFSET;
        let val_reconstructed = bit_decomp_32!(local_values, bit_col, FE, P);
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) * local_values[start_col + RANGE_CHECK_SELECTOR_OFFSET] * (val_reconstructed - local_values[start_col + RANGE_CHECK_SUM_OFFSET + 11])
        );
        yield_constr.constraint(bit_selector.unwrap_or(P::ONES) * local_values[start_col + RANGE_CHECK_SELECTOR_OFFSET] * local_values[bit_col + 30]);
    }
}

fn add_reduce_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    next_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    selector_col: usize,
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    let modulus = modulus();
    let modulus_u32 = get_u32_vec_from_literal(modulus);
    for i in 0..12 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[selector_col] *
            (
            local_values[start_col + REDUCE_MULTIPLICATION_OFFSET + Y_INPUT_OFFSET + i]
                - FE::from_canonical_u32(modulus_u32[i])
            )
        );
    }

    add_multiplication_constraints(
        local_values,
        next_values,
        yield_constr,
        start_col + REDUCE_MULTIPLICATION_OFFSET,
        bit_selector,
    );

    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[selector_col] *
            (
            local_values[start_col + REDUCE_X_OFFSET + i]
                - next_values[start_col + REDUCE_X_OFFSET + i]
            )
        );
    }

    for i in 0..12 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[selector_col] *
            (
            local_values[start_col + REDUCED_OFFSET + i]
                - next_values[start_col + REDUCED_OFFSET + i]
            )
        );
    }

    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + REDUCTION_ADDITION_OFFSET + ADDITION_CHECK_OFFSET]
                * (local_values[start_col + REDUCE_MULTIPLICATION_OFFSET + SUM_OFFSET + i]
                    - local_values[start_col + REDUCTION_ADDITION_OFFSET + ADDITION_X_OFFSET + i]),
        );
    }

    add_addition_constraints(
        local_values,
        yield_constr,
        start_col + REDUCTION_ADDITION_OFFSET,
        bit_selector,
    );

    for i in 0..24 {
        if i < 12 {
            yield_constr.constraint_transition(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + REDUCTION_ADDITION_OFFSET + ADDITION_CHECK_OFFSET]
                    * (local_values[start_col + REDUCED_OFFSET + i]
                        - local_values
                            [start_col + REDUCTION_ADDITION_OFFSET + ADDITION_Y_OFFSET + i]),
            );
        } else {
            yield_constr.constraint_transition(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + REDUCTION_ADDITION_OFFSET + ADDITION_CHECK_OFFSET]
                    * local_values[start_col + REDUCTION_ADDITION_OFFSET + ADDITION_Y_OFFSET + i],
            );
        }
    }

    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + REDUCTION_ADDITION_OFFSET + ADDITION_CHECK_OFFSET]
                * (local_values[start_col + REDUCE_X_OFFSET + i]
                    - local_values
                        [start_col + REDUCTION_ADDITION_OFFSET + ADDITION_SUM_OFFSET + i]),
        )
    }

}

fn add_fp2_mul_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    next_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    // for i in 0..12 {
    //     yield_constr.constraint_transition(local_values[start_col + X_0_Y_0_MULTIPLICATION_OFFSET + X_INPUT_OFFSET + i])
    // }
    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP2_FP2_X_INPUT_OFFSET + i] - next_values[start_col + FP2_FP2_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP2_FP2_Y_INPUT_OFFSET + i] - next_values[start_col + FP2_FP2_Y_INPUT_OFFSET + i])
        );
    }

    for i in 0..12 {
        yield_constr.constraint(bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + X_0_Y_0_MULTIPLICATION_OFFSET + X_INPUT_OFFSET + i] -
            local_values[start_col + FP2_FP2_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint(bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + X_0_Y_0_MULTIPLICATION_OFFSET + Y_INPUT_OFFSET + i] -
            local_values[start_col + FP2_FP2_Y_INPUT_OFFSET + i])
        );
        yield_constr.constraint(bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + X_0_Y_1_MULTIPLICATION_OFFSET + X_INPUT_OFFSET + i] -
            local_values[start_col + FP2_FP2_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint(bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + X_0_Y_1_MULTIPLICATION_OFFSET + Y_INPUT_OFFSET + i] -
            local_values[start_col + FP2_FP2_Y_INPUT_OFFSET + i + 12])
        );
        yield_constr.constraint(bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + X_1_Y_0_MULTIPLICATION_OFFSET + X_INPUT_OFFSET + i] -
            local_values[start_col + FP2_FP2_X_INPUT_OFFSET + i + 12])
        );
        yield_constr.constraint(bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + X_1_Y_0_MULTIPLICATION_OFFSET + Y_INPUT_OFFSET + i] -
            local_values[start_col + FP2_FP2_Y_INPUT_OFFSET + i])
        );
        yield_constr.constraint(bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + X_1_Y_1_MULTIPLICATION_OFFSET + X_INPUT_OFFSET + i] -
            local_values[start_col + FP2_FP2_X_INPUT_OFFSET + i + 12])
        );
        yield_constr.constraint(bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + X_1_Y_1_MULTIPLICATION_OFFSET + Y_INPUT_OFFSET + i] -
            local_values[start_col + FP2_FP2_Y_INPUT_OFFSET + i + 12])
        );
    }

    // constrain X_0*Y_0
    add_multiplication_constraints(
        local_values,
        next_values,
        yield_constr,
        start_col + X_0_Y_0_MULTIPLICATION_OFFSET,
        bit_selector,
    );


    // constrain X_1*Y_1
    add_multiplication_constraints(
        local_values,
        next_values,
        yield_constr,
        start_col + X_1_Y_1_MULTIPLICATION_OFFSET,
        bit_selector,
    );

    // constrain X0*Y0 with X0*Y0 + modulus^2
    for i in 0..24 {
        yield_constr.constraint_transition(bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + Z1_ADD_MODULUS_OFFSET + ADDITION_CHECK_OFFSET]
                * (local_values[start_col + Z1_ADD_MODULUS_OFFSET + ADDITION_X_OFFSET + i]
                    - local_values[start_col + X_0_Y_0_MULTIPLICATION_OFFSET + SUM_OFFSET + i]),
        );
    }

    // constrain modulus^2 with X0*Y0 + modulus^2
    let modulus = modulus();
    let modulus_sq_u32 = get_u32_vec_from_literal_24(modulus.clone() * modulus);
    for i in 0..24 {
        yield_constr.constraint_transition(bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + Z1_ADD_MODULUS_OFFSET + ADDITION_CHECK_OFFSET]
                * (local_values[start_col + Z1_ADD_MODULUS_OFFSET + ADDITION_Y_OFFSET + i]
                    - FE::from_canonical_u32(modulus_sq_u32[i])),
        );
    }

    // constrain X0*Y0 + modulus^2
    add_addition_constraints(local_values, yield_constr, start_col + Z1_ADD_MODULUS_OFFSET, bit_selector);

    // constrain X0*Y0 + modulus^2 with X0*Y0 + modulus^2 - X1Y1
    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + Z1_SUBTRACTION_OFFSET + SUBTRACTION_CHECK_OFFSET]
                * (local_values[start_col + Z1_SUBTRACTION_OFFSET + SUBTRACTION_X_OFFSET + i]
                    - local_values[start_col + Z1_ADD_MODULUS_OFFSET + ADDITION_SUM_OFFSET + i]),
        );
    }

    // constrain X1*Y1 + modulus^2 with X0*Y0 + modulus^2 - X1Y1
    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + Z1_SUBTRACTION_OFFSET + SUBTRACTION_CHECK_OFFSET]
                * (local_values[start_col + Z1_SUBTRACTION_OFFSET + SUBTRACTION_Y_OFFSET + i]
                    - local_values[start_col + X_1_Y_1_MULTIPLICATION_OFFSET + SUM_OFFSET + i]),
        );
    }

    // constrain X0*Y0 + modulus^2 - X1Y1
    add_subtraction_constraints(local_values, yield_constr, start_col + Z1_SUBTRACTION_OFFSET, bit_selector);

    // constrain X0*Y0 + modulus^2 - X1Y1 with reduction
    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + Z1_SUBTRACTION_OFFSET + SUBTRACTION_CHECK_OFFSET]
                * (local_values[start_col + Z1_SUBTRACTION_OFFSET + SUBTRACTION_DIFF_OFFSET + i]
                    - local_values[start_col + Z1_REDUCE_OFFSET + REDUCE_X_OFFSET + i]),
        );
    }



    // constrain reduction
    add_reduce_constraints(
        local_values,
        next_values,
        yield_constr,
        start_col + Z1_REDUCE_OFFSET,
        start_col + FP2_FP2_SELECTOR_OFFSET,
        bit_selector,
    );
    add_range_check_constraints(local_values, yield_constr, start_col + Z1_RANGECHECK_OFFSET, bit_selector);



    // constrain X_1*Y_0
    add_multiplication_constraints(
        local_values,
        next_values,
        yield_constr,
        start_col + X_0_Y_1_MULTIPLICATION_OFFSET,
        bit_selector,
    );



    // constrain X_1*Y_0
    add_multiplication_constraints(
        local_values,
        next_values,
        yield_constr,
        start_col + X_1_Y_0_MULTIPLICATION_OFFSET,
        bit_selector,
    );

    // constrain X0*Y1 with X0*Y1 + X1*Y0
    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + Z2_ADDITION_OFFSET + ADDITION_CHECK_OFFSET]
                * (local_values[start_col + Z2_ADDITION_OFFSET + ADDITION_X_OFFSET + i]
                    - local_values[start_col + X_0_Y_1_MULTIPLICATION_OFFSET + SUM_OFFSET + i]),
        );
    }

    // constrain X1*Y0 with X0*Y1 + X1*Y0
    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + Z2_ADDITION_OFFSET + ADDITION_CHECK_OFFSET]
                * (local_values[start_col + Z2_ADDITION_OFFSET + ADDITION_Y_OFFSET + i]
                    - local_values[start_col + X_1_Y_0_MULTIPLICATION_OFFSET + SUM_OFFSET + i]),
        );
    }

    // constrain X0*Y1 + X1*Y0
    add_addition_constraints(local_values, yield_constr, start_col + Z2_ADDITION_OFFSET, bit_selector);

    // constrain X0*Y1 + X1*Y0 with reduction
    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + Z2_ADDITION_OFFSET + ADDITION_CHECK_OFFSET]
                * (local_values[start_col + Z2_ADDITION_OFFSET + ADDITION_SUM_OFFSET + i]
                    - local_values[start_col + Z2_REDUCE_OFFSET + REDUCE_X_OFFSET + i]),
        );
    }

    // constrain reduction
    add_reduce_constraints(
        local_values,
        next_values,
        yield_constr,
        start_col + Z2_REDUCE_OFFSET,
        start_col + FP2_FP2_SELECTOR_OFFSET,
        bit_selector,
    );
    add_range_check_constraints(local_values, yield_constr, start_col + Z2_RANGECHECK_OFFSET, bit_selector);
}

pub fn add_fp2_fp_mul_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    next_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for i in 0..12 {
        for j in 0..2 {
            yield_constr.constraint_transition(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP2_FP_MUL_SELECTOR_OFFSET] *
                (local_values[start_col + FP2_FP_X_INPUT_OFFSET + j*12 + i] - next_values[start_col + FP2_FP_X_INPUT_OFFSET + j*12 + i])
            );
        }
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP_MUL_SELECTOR_OFFSET] *
            (local_values[start_col + FP2_FP_Y_INPUT_OFFSET + i] - next_values[start_col + FP2_FP_Y_INPUT_OFFSET + i])
        );
    }
    // constrain inputs to multiplication
    for i in 0..12 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP_MUL_SELECTOR_OFFSET] * (
                local_values[start_col + FP2_FP_X_INPUT_OFFSET + i] - local_values[start_col + X0_Y_MULTIPLICATION_OFFSET + X_INPUT_OFFSET + i]
            )
        );
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP_MUL_SELECTOR_OFFSET] * (
                local_values[start_col + FP2_FP_X_INPUT_OFFSET + 12 + i] - local_values[start_col + X1_Y_MULTIPLICATION_OFFSET + X_INPUT_OFFSET + i]
            )
        );
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP_MUL_SELECTOR_OFFSET] * (
                local_values[start_col + FP2_FP_Y_INPUT_OFFSET + i] - local_values[start_col + X0_Y_MULTIPLICATION_OFFSET + Y_INPUT_OFFSET + i]
            )
        );
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FP_MUL_SELECTOR_OFFSET] * (
                local_values[start_col + FP2_FP_Y_INPUT_OFFSET + i] - local_values[start_col + X1_Y_MULTIPLICATION_OFFSET + Y_INPUT_OFFSET + i]
            )
        );
    }
    add_multiplication_constraints(local_values, next_values, yield_constr, start_col + X0_Y_MULTIPLICATION_OFFSET, bit_selector);
    for i in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + X0_Y_REDUCE_OFFSET + REDUCTION_ADDITION_OFFSET + ADDITION_CHECK_OFFSET] * (
                local_values[start_col + X0_Y_REDUCE_OFFSET + REDUCTION_ADDITION_OFFSET + ADDITION_SUM_OFFSET + i] -
                local_values[start_col + X0_Y_MULTIPLICATION_OFFSET + SUM_OFFSET + i]
            )
        );
    }
    add_reduce_constraints(local_values, next_values, yield_constr, start_col + X0_Y_REDUCE_OFFSET, start_col + FP2_FP_MUL_SELECTOR_OFFSET, bit_selector);
    add_range_check_constraints(local_values, yield_constr, start_col + X0_Y_RANGECHECK_OFFSET, bit_selector);
    add_multiplication_constraints(local_values, next_values, yield_constr, start_col + X1_Y_MULTIPLICATION_OFFSET, bit_selector);
    for i in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + X1_Y_REDUCE_OFFSET + REDUCTION_ADDITION_OFFSET + ADDITION_CHECK_OFFSET] * (
                local_values[start_col + X1_Y_REDUCE_OFFSET + REDUCTION_ADDITION_OFFSET + ADDITION_SUM_OFFSET + i] -
                local_values[start_col + X1_Y_MULTIPLICATION_OFFSET + SUM_OFFSET + i]
            )
        );
    }
    add_reduce_constraints(local_values, next_values, yield_constr, start_col + X1_Y_REDUCE_OFFSET, start_col + FP2_FP_MUL_SELECTOR_OFFSET, bit_selector);
    add_range_check_constraints(local_values, yield_constr, start_col + X1_Y_RANGECHECK_OFFSET, bit_selector);
}


pub fn add_subtraction_with_reduction_constranints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    let modulus = get_u32_vec_from_literal(modulus());
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                FE::from_canonical_u32(modulus[i])
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                FE::from_canonical_u32(modulus[i])
            )
        );
    }
    add_addition_fp2_constraints(local_values, yield_constr, start_col, bit_selector);
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_X_OFFSET + i] -
                local_values[start_col + FP2_ADDITION_0_OFFSET + FP_ADDITION_SUM_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_X_OFFSET + i] -
                local_values[start_col + FP2_ADDITION_1_OFFSET + FP_ADDITION_SUM_OFFSET + i]
            )
        );
    }
    add_subtraction_fp2_constraints(local_values, yield_constr, start_col + FP2_ADDITION_TOTAL, bit_selector);
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_DIFF_OFFSET + i] -
                local_values[start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_X_OFFSET + i]
            )
        );
    }
    add_fp_reduce_single_constraints(local_values, yield_constr, start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL, bit_selector);
    add_range_check_constraints(local_values, yield_constr, start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL, bit_selector);
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_DIFF_OFFSET + i] -
                local_values[start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCE_X_OFFSET + i]
            )
        );
    }
    add_fp_reduce_single_constraints(local_values, yield_constr, start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL, bit_selector);
    add_range_check_constraints(local_values, yield_constr, start_col + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL*2 + RANGE_CHECK_TOTAL, bit_selector);
}

pub fn add_addition_with_reduction_constranints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_addition_fp2_constraints(local_values, yield_constr, start_col, bit_selector);
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP2_ADDITION_0_OFFSET + FP_ADDITION_SUM_OFFSET + i] -
                local_values[start_col + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_X_OFFSET + i]
            )
        );
    }
    add_fp_reduce_single_constraints(local_values, yield_constr, start_col + FP2_ADDITION_TOTAL, bit_selector);
    add_range_check_constraints(local_values, yield_constr, start_col + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL, bit_selector);
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP2_ADDITION_1_OFFSET + FP_ADDITION_SUM_OFFSET + i] -
                local_values[start_col + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCE_X_OFFSET + i]
            )
        );
    }
    add_fp_reduce_single_constraints(local_values, yield_constr, start_col + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL, bit_selector);
    add_range_check_constraints(local_values, yield_constr, start_col + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL*2 + RANGE_CHECK_TOTAL, bit_selector);
}

pub fn add_non_residue_multiplication_constraints<F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize,
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    let modulus = get_u32_vec_from_literal(modulus());
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_CHECK_OFFSET] *
            (local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_X_OFFSET + i] - local_values[start_col + FP2_NON_RESIDUE_MUL_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_CHECK_OFFSET] *
            (local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_Y_OFFSET + i] - FE::from_canonical_u32(modulus[i]))
        );
    }
    add_addition_fp_constraints(local_values, yield_constr, start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET, bit_selector);
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_TOTAL + FP_SUBTRACTION_CHECK_OFFSET] *
            (local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_TOTAL + FP_SUBTRACTION_X_OFFSET + i] - local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_SUM_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_TOTAL + FP_SUBTRACTION_CHECK_OFFSET] *
            (local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_TOTAL + FP_SUBTRACTION_Y_OFFSET + i] - local_values[start_col + FP2_NON_RESIDUE_MUL_INPUT_OFFSET + i + 12])
        );
    }
    add_subtraction_fp_constraints(local_values, yield_constr, start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_TOTAL, bit_selector);
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_TOTAL + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_SUB_OFFSET + FP_ADDITION_TOTAL + FP_SUBTRACTION_DIFF_OFFSET + i] -
                local_values[start_col + FP2_NON_RESIDUE_MUL_Z0_REDUCE_OFFSET + FP_SINGLE_REDUCE_X_OFFSET + i]
            )
        );
    }
    add_fp_reduce_single_constraints(local_values, yield_constr, start_col + FP2_NON_RESIDUE_MUL_Z0_REDUCE_OFFSET, bit_selector);
    add_range_check_constraints(local_values, yield_constr, start_col + FP2_NON_RESIDUE_MUL_Z0_RANGECHECK_OFFSET, bit_selector);
    
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_ADD_OFFSET + FP_ADDITION_CHECK_OFFSET] *
            (local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_ADD_OFFSET + FP_ADDITION_X_OFFSET + i] - local_values[start_col + FP2_NON_RESIDUE_MUL_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_ADD_OFFSET + FP_ADDITION_CHECK_OFFSET] *
            (local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_ADD_OFFSET + FP_ADDITION_Y_OFFSET + i] - local_values[start_col + FP2_NON_RESIDUE_MUL_INPUT_OFFSET + i + 12])
        );
    }
    add_addition_fp_constraints(local_values, yield_constr, start_col + FP2_NON_RESIDUE_MUL_C0_C1_ADD_OFFSET, bit_selector);
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_ADD_OFFSET + FP_ADDITION_TOTAL + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP2_NON_RESIDUE_MUL_C0_C1_ADD_OFFSET + FP_ADDITION_SUM_OFFSET + i] -
                local_values[start_col + FP2_NON_RESIDUE_MUL_Z1_REDUCE_OFFSET + FP_SINGLE_REDUCE_X_OFFSET + i]
            )
        );
    }
    add_fp_reduce_single_constraints(local_values, yield_constr, start_col + FP2_NON_RESIDUE_MUL_Z1_REDUCE_OFFSET, bit_selector);
    add_range_check_constraints(local_values, yield_constr, start_col + FP2_NON_RESIDUE_MUL_Z1_RANGECHECK_OFFSET, bit_selector);
}

pub fn add_addition_fp6_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_addition_fp2_constraints(local_values, yield_constr, start_col + FP6_ADDITION_0_OFFSET, bit_selector);
    add_addition_fp2_constraints(local_values, yield_constr, start_col + FP6_ADDITION_1_OFFSET, bit_selector);
    add_addition_fp2_constraints(local_values, yield_constr, start_col + FP6_ADDITION_2_OFFSET, bit_selector);
}

pub fn add_addition_with_reduction_constranints_fp6<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_addition_fp6_constraints(local_values, yield_constr, start_col, bit_selector);
    for j in 0..6 {
        let fp2_offset = if j < 2 {
            FP6_ADDITION_0_OFFSET
        } else if j < 4 {
            FP6_ADDITION_1_OFFSET
        } else {
            FP6_ADDITION_2_OFFSET
        };
        let fp_offset = if j%2 == 0 {
            FP2_ADDITION_0_OFFSET
        } else {
            FP2_ADDITION_1_OFFSET
        };
        for i in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + fp2_offset + fp_offset + FP_ADDITION_CHECK_OFFSET] * (
                    local_values[start_col + fp2_offset + fp_offset + FP_ADDITION_SUM_OFFSET + i] -
                    local_values[start_col + FP6_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL) * j + FP_SINGLE_REDUCE_X_OFFSET + i]
                )
            );
        }
        add_fp_reduce_single_constraints(local_values, yield_constr, start_col + FP6_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL) * j, bit_selector);
        add_range_check_constraints(local_values, yield_constr, start_col + FP6_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL) * j + FP_SINGLE_REDUCE_TOTAL, bit_selector);
    }
}

pub fn add_subtraction_fp6_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_subtraction_fp2_constraints(local_values, yield_constr, start_col + FP6_SUBTRACTION_0_OFFSET, bit_selector);
    add_subtraction_fp2_constraints(local_values, yield_constr, start_col + FP6_SUBTRACTION_1_OFFSET, bit_selector);
    add_subtraction_fp2_constraints(local_values, yield_constr, start_col + FP6_SUBTRACTION_2_OFFSET, bit_selector);
}

pub fn add_negate_fp6_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_addition_fp6_constraints(local_values, yield_constr, start_col, bit_selector);
    let mod_u32 = get_u32_vec_from_literal(modulus());
    for i in 0..12 {
        for j in 0..3 {
            let fp2_offset = if j == 0 {
                FP6_ADDITION_0_OFFSET
            } else if j == 1 {
                FP6_ADDITION_1_OFFSET
            } else {
                FP6_ADDITION_2_OFFSET
            };
            for k in 0..2 {
                let fp_offset = if k == 0 {
                    FP2_ADDITION_0_OFFSET
                } else {
                    FP2_ADDITION_1_OFFSET
                };
                yield_constr.constraint(
                    bit_selector.unwrap_or(P::ONES) *
                    local_values[start_col + fp2_offset + fp_offset + FP_ADDITION_CHECK_OFFSET] * (
                        local_values[start_col + fp2_offset + fp_offset + FP_ADDITION_SUM_OFFSET + i] - FE::from_canonical_u32(mod_u32[i])
                    )
                );
            }
        }
    }
}

pub fn add_subtraction_with_reduction_constranints_fp6<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize, // Starting column of your multiplication trace
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    add_addition_fp6_constraints(local_values, yield_constr, start_col, bit_selector);
    add_subtraction_fp6_constraints(local_values, yield_constr, start_col + FP6_ADDITION_TOTAL, bit_selector);

    let modulus = get_u32_vec_from_literal(modulus());
    for j in 0..6 {
        let (fp2_add_offset, fp2_sub_offset) = if j < 2 {
            (FP6_ADDITION_0_OFFSET, FP6_SUBTRACTION_0_OFFSET)
        } else if j < 4 {
            (FP6_ADDITION_1_OFFSET, FP6_SUBTRACTION_1_OFFSET)
        } else {
            (FP6_ADDITION_2_OFFSET, FP6_SUBTRACTION_2_OFFSET)
        };
        let (_fp_add_offset, fp_sub_offset) = if j%2 == 0 {
            (FP2_ADDITION_0_OFFSET, FP2_SUBTRACTION_0_OFFSET)
        } else {
            (FP2_ADDITION_1_OFFSET, FP2_SUBTRACTION_1_OFFSET)
        };
        for i in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + fp2_add_offset + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                    local_values[start_col + fp2_add_offset + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                    FE::from_canonical_u32(modulus[i])
                )
            );
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + fp2_add_offset + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                    local_values[start_col + fp2_add_offset + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                    FE::from_canonical_u32(modulus[i])
                )
            );
        }
        for i in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP6_ADDITION_TOTAL + fp2_sub_offset + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                    local_values[start_col + FP6_ADDITION_TOTAL + fp2_sub_offset + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_X_OFFSET + i] -
                    local_values[start_col + fp2_add_offset + FP2_ADDITION_0_OFFSET + FP_ADDITION_SUM_OFFSET + i]
                )
            );
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP6_ADDITION_TOTAL + fp2_sub_offset + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                    local_values[start_col + FP6_ADDITION_TOTAL + fp2_sub_offset + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_X_OFFSET + i] -
                    local_values[start_col + fp2_add_offset + FP2_ADDITION_1_OFFSET + FP_ADDITION_SUM_OFFSET + i]
                )
            );
        }
        for i in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP6_ADDITION_TOTAL + fp2_sub_offset + fp_sub_offset + FP_SUBTRACTION_CHECK_OFFSET] * (
                    local_values[start_col + FP6_ADDITION_TOTAL + fp2_sub_offset + fp_sub_offset + FP_SUBTRACTION_DIFF_OFFSET + i] -
                    local_values[start_col + FP6_ADDITION_TOTAL + FP6_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*j + FP_SINGLE_REDUCE_X_OFFSET + i]
                )
            );
        }
        add_fp_reduce_single_constraints(local_values, yield_constr, start_col + FP6_ADDITION_TOTAL + FP6_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*j, bit_selector);
        add_range_check_constraints(local_values, yield_constr, start_col + FP6_ADDITION_TOTAL + FP6_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*j + FP_SINGLE_REDUCE_TOTAL, bit_selector);
    }
}

pub fn add_non_residue_multiplication_fp6_constraints<F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize,
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for i in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_NON_RESIDUE_MUL_CHECK_OFFSET] *
            (local_values[start_col + FP6_NON_RESIDUE_MUL_INPUT_OFFSET + i + 48] - local_values[start_col + FP6_NON_RESIDUE_MUL_C2 + FP2_NON_RESIDUE_MUL_INPUT_OFFSET + i])
        );
    }
    add_non_residue_multiplication_constraints(local_values, yield_constr, start_col + FP6_NON_RESIDUE_MUL_C2, bit_selector);
}

pub fn add_fp6_multiplication_constraints<F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    next_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize,
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for i in 0..24*3 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i] - next_values[start_col + FP6_MUL_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i] - next_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i])
        );
    }

    // T0
    for i in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T0_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i] - local_values[start_col + FP6_MUL_T0_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T0_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i] - local_values[start_col + FP6_MUL_T0_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i])
        );
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP6_MUL_T0_CALC_OFFSET, bit_selector);

    // T1
    for i in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T1_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 24] - local_values[start_col + FP6_MUL_T1_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T1_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 24] - local_values[start_col + FP6_MUL_T1_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i])
        );
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP6_MUL_T1_CALC_OFFSET, bit_selector);

    // T2
    for i in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T2_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 48] - local_values[start_col + FP6_MUL_T2_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T2_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 48] - local_values[start_col + FP6_MUL_T2_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i])
        );
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP6_MUL_T2_CALC_OFFSET, bit_selector);

    // T3
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 24]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 24 + 12]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 48]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 48 + 12]
            )
        );
    }

    add_addition_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T3_CALC_OFFSET, bit_selector);

    // T4
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 24]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 24 + 12]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 48]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 48 + 12]
            )
        );
    }

    add_addition_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T4_CALC_OFFSET, bit_selector);

    // T5
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T5_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T5_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T5_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T3_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T5_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i + 12])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T5_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T5_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T5_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T4_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T5_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i + 12])
        );
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP6_MUL_T5_CALC_OFFSET, bit_selector);

    // T6
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T5_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T5_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T1_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T1_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
    }

    add_subtraction_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T6_CALC_OFFSET, bit_selector);

    // T7
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T6_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T2_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T2_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
    }

    add_subtraction_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T7_CALC_OFFSET, bit_selector);

    // T8
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T8_CALC_OFFSET + FP2_NON_RESIDUE_MUL_CHECK_OFFSET] *
            (
                local_values[start_col + FP6_MUL_T8_CALC_OFFSET + FP2_NON_RESIDUE_MUL_INPUT_OFFSET + i] - local_values[start_col + FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T8_CALC_OFFSET + FP2_NON_RESIDUE_MUL_CHECK_OFFSET] *
            (
                local_values[start_col + FP6_MUL_T8_CALC_OFFSET + FP2_NON_RESIDUE_MUL_INPUT_OFFSET + i + 12] - local_values[start_col + FP6_MUL_T7_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
    }
    add_non_residue_multiplication_constraints(local_values, yield_constr, start_col + FP6_MUL_T8_CALC_OFFSET, bit_selector);

    // X calc offset
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_X_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_X_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T8_CALC_OFFSET + FP2_NON_RESIDUE_MUL_Z0_REDUCE_OFFSET + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_X_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_X_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T8_CALC_OFFSET + FP2_NON_RESIDUE_MUL_Z1_REDUCE_OFFSET + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_X_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_X_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T0_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_X_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_X_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T0_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
    }

    add_addition_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_X_CALC_OFFSET, bit_selector);

    // T9
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 12]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 24]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 24 + 12]
            )
        );
    }

    add_addition_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T9_CALC_OFFSET, bit_selector);

    // T10
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 12]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 24]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 24 + 12]
            )
        );
    }

    add_addition_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T10_CALC_OFFSET, bit_selector);

    // T11
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T11_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T11_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T11_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T9_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T11_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i + 12])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T11_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T11_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T11_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T10_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T11_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i + 12])
        );
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP6_MUL_T11_CALC_OFFSET, bit_selector);

    // T12
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T11_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T11_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T0_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T0_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
    }

    add_subtraction_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T12_CALC_OFFSET, bit_selector);

    // T13
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T12_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T1_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T1_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
    }

    add_subtraction_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T13_CALC_OFFSET, bit_selector);

    // T14
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T14_CALC_OFFSET + FP2_NON_RESIDUE_MUL_CHECK_OFFSET] *
            (
                local_values[start_col + FP6_MUL_T14_CALC_OFFSET + FP2_NON_RESIDUE_MUL_INPUT_OFFSET + i] - local_values[start_col + FP6_MUL_T2_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T14_CALC_OFFSET + FP2_NON_RESIDUE_MUL_CHECK_OFFSET] *
            (
                local_values[start_col + FP6_MUL_T14_CALC_OFFSET + FP2_NON_RESIDUE_MUL_INPUT_OFFSET + i + 12] - local_values[start_col + FP6_MUL_T2_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
    }
    add_non_residue_multiplication_constraints(local_values, yield_constr, start_col + FP6_MUL_T14_CALC_OFFSET, bit_selector);

    // Y calc offset
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_Y_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_Y_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_Y_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_Y_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T13_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_Y_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_Y_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T14_CALC_OFFSET + FP2_NON_RESIDUE_MUL_Z0_REDUCE_OFFSET + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_Y_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_Y_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T14_CALC_OFFSET + FP2_NON_RESIDUE_MUL_Z1_REDUCE_OFFSET + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
    }

    add_addition_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_Y_CALC_OFFSET, bit_selector);

    // T15
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 12]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 48]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_X_INPUT_OFFSET + i + 48 + 12]
            )
        );
    }

    add_addition_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T15_CALC_OFFSET, bit_selector);

    // T16
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 12]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 48]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_Y_INPUT_OFFSET + i + 48 + 12]
            )
        );
    }

    add_addition_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T16_CALC_OFFSET, bit_selector);

    // T17
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T17_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T17_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T17_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T15_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T17_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i + 12])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T17_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T17_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T17_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_MUL_T16_CALC_OFFSET + FP2_ADDITION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i] - local_values[start_col + FP6_MUL_T17_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i + 12])
        );
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP6_MUL_T17_CALC_OFFSET, bit_selector);

    // T18
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T17_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T17_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T0_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T0_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
    }

    add_subtraction_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T18_CALC_OFFSET, bit_selector);

    // T19
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T18_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_0_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T2_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_1_OFFSET + FP_SUBTRACTION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T2_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
    }

    add_subtraction_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_T19_CALC_OFFSET, bit_selector);

    // Z calc offset
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_Z_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_Z_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_Z_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_Z_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_X_OFFSET + i] -
                local_values[start_col + FP6_MUL_T19_CALC_OFFSET + FP2_ADDITION_TOTAL + FP2_SUBTRACTION_TOTAL + FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL + FP_SINGLE_REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_Z_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_Z_CALC_OFFSET + FP2_ADDITION_0_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T1_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_MUL_Z_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_CHECK_OFFSET] * (
                local_values[start_col + FP6_MUL_Z_CALC_OFFSET + FP2_ADDITION_1_OFFSET + FP_ADDITION_Y_OFFSET + i] -
                local_values[start_col + FP6_MUL_T1_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET + i]
            )
        );
    }

    add_addition_with_reduction_constranints(local_values, yield_constr, start_col + FP6_MUL_Z_CALC_OFFSET, bit_selector);
}

pub fn add_fp12_multiplication_constraints<F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
    >(
    local_values: &[P],
    next_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize,
    bit_selector: Option<P>,
    ) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for i in 0..24*3*2 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP12_MUL_SELECTOR_OFFSET] *
            (local_values[start_col + FP12_MUL_X_INPUT_OFFSET + i] - next_values[start_col + FP12_MUL_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP12_MUL_SELECTOR_OFFSET] *
            (local_values[start_col + FP12_MUL_Y_INPUT_OFFSET + i] - next_values[start_col + FP12_MUL_Y_INPUT_OFFSET + i])
        );
    }

    // T0
    for i in 0..24*3 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP12_MUL_T0_CALC_OFFSET + FP6_MUL_SELECTOR_OFFSET] *
            (local_values[start_col + FP12_MUL_T0_CALC_OFFSET + FP6_MUL_X_INPUT_OFFSET + i] - local_values[start_col + FP12_MUL_X_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP12_MUL_T0_CALC_OFFSET + FP6_MUL_SELECTOR_OFFSET] *
            (local_values[start_col + FP12_MUL_T0_CALC_OFFSET + FP6_MUL_Y_INPUT_OFFSET + i] - local_values[start_col + FP12_MUL_Y_INPUT_OFFSET + i])
        );
    }
    add_fp6_multiplication_constraints(local_values, next_values, yield_constr, start_col + FP12_MUL_T0_CALC_OFFSET, bit_selector);

    // T1
    for i in 0..24*3 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP12_MUL_T1_CALC_OFFSET + FP6_MUL_SELECTOR_OFFSET] *
            (local_values[start_col + FP12_MUL_T1_CALC_OFFSET + FP6_MUL_X_INPUT_OFFSET + i] - local_values[start_col + FP12_MUL_X_INPUT_OFFSET + i + 24*3])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP12_MUL_T1_CALC_OFFSET + FP6_MUL_SELECTOR_OFFSET] *
            (local_values[start_col + FP12_MUL_T1_CALC_OFFSET + FP6_MUL_Y_INPUT_OFFSET + i] - local_values[start_col + FP12_MUL_Y_INPUT_OFFSET + i + 24*3])
        );
    }
    add_fp6_multiplication_constraints(local_values, next_values, yield_constr, start_col + FP12_MUL_T1_CALC_OFFSET, bit_selector);
    
    // T2
    for i in 0..6 {
        let fp2_offset = if i < 2 {
            FP6_MUL_X_CALC_OFFSET
        } else if i < 4 {
            FP6_MUL_Y_CALC_OFFSET
        } else {
            FP6_MUL_Z_CALC_OFFSET
        };
        let fp_offset = i%2;
        for j in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_T2_CALC_OFFSET + FP6_NON_RESIDUE_MUL_CHECK_OFFSET] *
                (local_values[start_col + FP12_MUL_T2_CALC_OFFSET + FP6_NON_RESIDUE_MUL_INPUT_OFFSET + i*12 + j] - 
                local_values[start_col + FP12_MUL_T1_CALC_OFFSET + fp2_offset + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*fp_offset + FP_SINGLE_REDUCED_OFFSET + j])
            );
        }
    }
    add_non_residue_multiplication_fp6_constraints(local_values, yield_constr, start_col + FP12_MUL_T2_CALC_OFFSET, bit_selector);

    // X
    for i in 0..6 {
        let (fp2_offset_l, fp2_offset_r) = if i < 2 {
            (FP6_ADDITION_0_OFFSET, FP6_MUL_X_CALC_OFFSET)
        } else if i < 4 {
            (FP6_ADDITION_1_OFFSET, FP6_MUL_Y_CALC_OFFSET)
        } else {
            (FP6_ADDITION_2_OFFSET, FP6_MUL_Z_CALC_OFFSET)
        };
        let (fp_offset, num_redn) = if i%2 == 0 {
            (FP2_ADDITION_0_OFFSET, 0)
        } else {
            (FP2_ADDITION_1_OFFSET, 1)
        };
        for j in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_X_CALC_OFFSET + fp2_offset_l + fp_offset + FP_ADDITION_CHECK_OFFSET] *
                (local_values[start_col + FP12_MUL_X_CALC_OFFSET + fp2_offset_l + fp_offset + FP_ADDITION_X_OFFSET + j] -
                local_values[start_col + FP12_MUL_T0_CALC_OFFSET + fp2_offset_r + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*num_redn + FP_SINGLE_REDUCED_OFFSET + j])
            );
            if i < 2 {
                let y_offset = if i==0 {
                    FP2_NON_RESIDUE_MUL_Z0_REDUCE_OFFSET
                } else {
                    FP2_NON_RESIDUE_MUL_Z1_REDUCE_OFFSET
                };
                yield_constr.constraint(
                    bit_selector.unwrap_or(P::ONES) *
                    local_values[start_col + FP12_MUL_X_CALC_OFFSET + fp2_offset_l + fp_offset + FP_ADDITION_CHECK_OFFSET] *
                    (local_values[start_col + FP12_MUL_X_CALC_OFFSET + fp2_offset_l + fp_offset + FP_ADDITION_Y_OFFSET + j] -
                    local_values[start_col + FP12_MUL_T2_CALC_OFFSET + FP6_NON_RESIDUE_MUL_C2 + y_offset + FP_SINGLE_REDUCED_OFFSET + j])
                )
            } else {
                yield_constr.constraint(
                    bit_selector.unwrap_or(P::ONES) *
                    local_values[start_col + FP12_MUL_X_CALC_OFFSET + fp2_offset_l + fp_offset + FP_ADDITION_CHECK_OFFSET] *
                    (local_values[start_col + FP12_MUL_X_CALC_OFFSET + fp2_offset_l + fp_offset + FP_ADDITION_Y_OFFSET + j] -
                    local_values[start_col + FP12_MUL_T2_CALC_OFFSET + FP6_NON_RESIDUE_MUL_INPUT_OFFSET + (i-2)*12 + j])
                );
            }
        }
    }
    add_addition_with_reduction_constranints_fp6(local_values, yield_constr, start_col + FP12_MUL_X_CALC_OFFSET, bit_selector);

    // T3
    for i in 0..6 {
        let fp2_offset = if i < 2 {
            FP6_ADDITION_0_OFFSET
        } else if i < 4 {
            FP6_ADDITION_1_OFFSET
        } else {
            FP6_ADDITION_2_OFFSET
        };
        let fp_offset = if i%2 == 0 {
            FP2_ADDITION_0_OFFSET
        } else {
            FP2_ADDITION_1_OFFSET
        };
        for j in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_T3_CALC_OFFSET + fp2_offset + fp_offset + FP_ADDITION_CHECK_OFFSET] *
                (local_values[start_col + FP12_MUL_T3_CALC_OFFSET + fp2_offset + fp_offset + FP_ADDITION_X_OFFSET + j] -
                local_values[start_col + FP12_MUL_X_INPUT_OFFSET + i*12 + j])
            );
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_T3_CALC_OFFSET + fp2_offset + fp_offset + FP_ADDITION_CHECK_OFFSET] *
                (local_values[start_col + FP12_MUL_T3_CALC_OFFSET + fp2_offset + fp_offset + FP_ADDITION_Y_OFFSET + j] -
                local_values[start_col + FP12_MUL_X_INPUT_OFFSET + i*12 + j + 24*3])
            );
        }
    }
    add_addition_with_reduction_constranints_fp6(local_values, yield_constr, start_col + FP12_MUL_T3_CALC_OFFSET, bit_selector);

    // T4
    for i in 0..6 {
        let fp2_offset = if i < 2 {
            FP6_ADDITION_0_OFFSET
        } else if i < 4 {
            FP6_ADDITION_1_OFFSET
        } else {
            FP6_ADDITION_2_OFFSET
        };
        let fp_offset = if i%2 == 0 {
            FP2_ADDITION_0_OFFSET
        } else {
            FP2_ADDITION_1_OFFSET
        };
        for j in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_T4_CALC_OFFSET + fp2_offset + fp_offset + FP_ADDITION_CHECK_OFFSET] *
                (local_values[start_col + FP12_MUL_T4_CALC_OFFSET + fp2_offset + fp_offset + FP_ADDITION_X_OFFSET + j] -
                local_values[start_col + FP12_MUL_Y_INPUT_OFFSET + i*12 + j])
            );
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_T4_CALC_OFFSET + fp2_offset + fp_offset + FP_ADDITION_CHECK_OFFSET] *
                (local_values[start_col + FP12_MUL_T4_CALC_OFFSET + fp2_offset + fp_offset + FP_ADDITION_Y_OFFSET + j] -
                local_values[start_col + FP12_MUL_Y_INPUT_OFFSET + i*12 + j + 24*3])
            );
        }
    }
    add_addition_with_reduction_constranints_fp6(local_values, yield_constr, start_col + FP12_MUL_T4_CALC_OFFSET, bit_selector);

    // T5
    for i in 0..6 {
        for j in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_T5_CALC_OFFSET + FP6_MUL_SELECTOR_OFFSET] *
                (local_values[start_col + FP12_MUL_T5_CALC_OFFSET + FP6_MUL_X_INPUT_OFFSET + i*12 + j] -
                local_values[start_col + FP12_MUL_T3_CALC_OFFSET + FP6_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*i + FP_SINGLE_REDUCED_OFFSET + j])
            );
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_T5_CALC_OFFSET + FP6_MUL_SELECTOR_OFFSET] *
                (local_values[start_col + FP12_MUL_T5_CALC_OFFSET + FP6_MUL_Y_INPUT_OFFSET + i*12 + j] -
                local_values[start_col + FP12_MUL_T4_CALC_OFFSET + FP6_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*i + FP_SINGLE_REDUCED_OFFSET + j])
            );
        }
    }
    add_fp6_multiplication_constraints(local_values, next_values, yield_constr, start_col + FP12_MUL_T5_CALC_OFFSET, bit_selector);

    // T6
    for i in 0..6 {
        let (fp2_offset_lx, fp2_offset_ly, fp2_offset_r) = if i < 2 {
            (FP6_ADDITION_0_OFFSET, FP6_SUBTRACTION_0_OFFSET, FP6_MUL_X_CALC_OFFSET)
        } else if i < 4 {
            (FP6_ADDITION_1_OFFSET, FP6_SUBTRACTION_1_OFFSET, FP6_MUL_Y_CALC_OFFSET)
        } else {
            (FP6_ADDITION_2_OFFSET, FP6_SUBTRACTION_2_OFFSET, FP6_MUL_Z_CALC_OFFSET)
        };
        let (fp_offset_x, fp_offset_y, num_redn) = if i%2 == 0 {
            (FP2_ADDITION_0_OFFSET, FP2_SUBTRACTION_0_OFFSET, 0)
        } else {
            (FP2_ADDITION_1_OFFSET, FP2_SUBTRACTION_1_OFFSET, 1)
        };
        for j in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_T6_CALC_OFFSET + fp2_offset_lx + fp_offset_x + FP_ADDITION_CHECK_OFFSET] *
                (local_values[start_col + FP12_MUL_T6_CALC_OFFSET + fp2_offset_lx + fp_offset_x + FP_ADDITION_X_OFFSET + j] -
                local_values[start_col + FP12_MUL_T5_CALC_OFFSET + fp2_offset_r + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*num_redn + FP_SINGLE_REDUCED_OFFSET + j])
            );
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_T6_CALC_OFFSET + FP6_ADDITION_TOTAL + fp2_offset_ly + fp_offset_y + FP_SUBTRACTION_CHECK_OFFSET] *
                (local_values[start_col + FP12_MUL_T6_CALC_OFFSET + FP6_ADDITION_TOTAL + fp2_offset_ly + fp_offset_y + FP_SUBTRACTION_Y_OFFSET + j] -
                local_values[start_col + FP12_MUL_T0_CALC_OFFSET + fp2_offset_r + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*num_redn + FP_SINGLE_REDUCED_OFFSET + j])
            );
        }
    }
    add_subtraction_with_reduction_constranints_fp6(local_values, yield_constr, start_col + FP12_MUL_T6_CALC_OFFSET, bit_selector);

    // Y
    for i in 0..6 {
        let (fp2_offset_lx, fp2_offset_ly, fp2_offset_r) = if i < 2 {
            (FP6_ADDITION_0_OFFSET, FP6_SUBTRACTION_0_OFFSET, FP6_MUL_X_CALC_OFFSET)
        } else if i < 4 {
            (FP6_ADDITION_1_OFFSET, FP6_SUBTRACTION_1_OFFSET, FP6_MUL_Y_CALC_OFFSET)
        } else {
            (FP6_ADDITION_2_OFFSET, FP6_SUBTRACTION_2_OFFSET, FP6_MUL_Z_CALC_OFFSET)
        };
        let (fp_offset_x, fp_offset_y, num_redn) = if i%2 == 0 {
            (FP2_ADDITION_0_OFFSET, FP2_SUBTRACTION_0_OFFSET, 0)
        } else {
            (FP2_ADDITION_1_OFFSET, FP2_SUBTRACTION_1_OFFSET, 1)
        };
        for j in 0..12 {
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_Y_CALC_OFFSET + fp2_offset_lx + fp_offset_x + FP_ADDITION_CHECK_OFFSET] *
                (local_values[start_col + FP12_MUL_Y_CALC_OFFSET + fp2_offset_lx + fp_offset_x + FP_ADDITION_X_OFFSET + j] -
                local_values[start_col + FP12_MUL_T6_CALC_OFFSET + FP6_ADDITION_TOTAL + FP6_SUBTRACTION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*i + FP_SINGLE_REDUCED_OFFSET + j])
            );
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_MUL_Y_CALC_OFFSET + FP6_ADDITION_TOTAL + fp2_offset_ly + fp_offset_y + FP_SUBTRACTION_CHECK_OFFSET] *
                (local_values[start_col + FP12_MUL_Y_CALC_OFFSET + FP6_ADDITION_TOTAL + fp2_offset_ly + fp_offset_y + FP_SUBTRACTION_Y_OFFSET + j] -
                local_values[start_col + FP12_MUL_T1_CALC_OFFSET + fp2_offset_r + FP2_ADDITION_TOTAL + (FP_SINGLE_REDUCE_TOTAL + RANGE_CHECK_TOTAL)*num_redn + FP_SINGLE_REDUCED_OFFSET + j])
            );
        }
    }
    add_subtraction_with_reduction_constranints_fp6(local_values, yield_constr, start_col + FP12_MUL_Y_CALC_OFFSET, bit_selector);
}

pub fn add_fp2_forbenius_map_constraints<F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    local_values: &[P],
    next_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize,
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for i in 0..24 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
            (local_values[start_col + FP2_FORBENIUS_MAP_INPUT_OFFSET + i] -
            next_values[start_col + FP2_FORBENIUS_MAP_INPUT_OFFSET + i])
        );
    }
    yield_constr.constraint_transition(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP2_FORBENIUS_MAP_POW_OFFSET] -
        next_values[start_col + FP2_FORBENIUS_MAP_POW_OFFSET])
    );
    yield_constr.constraint_first_row(
        local_values[start_col + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
        local_values[start_col + FP2_FORBENIUS_MAP_ROW_NUM]
    );
    yield_constr.constraint_transition(
        local_values[start_col + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP2_FORBENIUS_MAP_ROW_NUM] + P::ONES -
        next_values[start_col + FP2_FORBENIUS_MAP_ROW_NUM])
    );
    yield_constr.constraint(
        local_values[start_col + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
        local_values[start_col + FP2_FORBENIUS_MAP_MUL_RES_ROW] *
        (local_values[start_col + FP2_FORBENIUS_MAP_ROW_NUM] - FE::from_canonical_u32(11))
    );
    yield_constr.constraint(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP2_FORBENIUS_MAP_DIV_OFFSET] * FE::TWO +
        local_values[start_col + FP2_FORBENIUS_MAP_REM_OFFSET] -
        local_values[start_col + FP2_FORBENIUS_MAP_POW_OFFSET])
    );
    let bit = local_values[start_col + FP2_FORBENIUS_MAP_REM_OFFSET];
    let forbenius_coefficients = Fp2::forbenius_coefficients().iter().map(|fp| fp.0).collect::<Vec<[u32; 12]>>();
    let y = (0..12).map(|i|
        (P::ONES - bit) * FE::from_canonical_u32(forbenius_coefficients[0][i]) + bit * FE::from_canonical_u32(forbenius_coefficients[1][i])
    ).collect::<Vec<P>>();
    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + MULTIPLICATION_SELECTOR_OFFSET] *
            (local_values[start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + X_INPUT_OFFSET + i] -
            local_values[start_col + FP2_FORBENIUS_MAP_INPUT_OFFSET + 12 + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + MULTIPLICATION_SELECTOR_OFFSET] *
            (local_values[start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + Y_INPUT_OFFSET + i] -
            y[i])
        );
    }
    add_multiplication_constraints(local_values, next_values, yield_constr, start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET, bit_selector);
    for i in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP2_FORBENIUS_MAP_MUL_RES_ROW] *
            (local_values[start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + SUM_OFFSET + i] -
            local_values[start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS + REDUCE_X_OFFSET + i])
        );
    }
    add_reduce_constraints(local_values, next_values, yield_constr, start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS, start_col + FP2_FORBENIUS_MAP_SELECTOR_OFFSET, bit_selector);
    add_range_check_constraints(local_values, yield_constr, start_col + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS + REDUCTION_TOTAL, bit_selector);
}

pub fn add_fp6_forbenius_map_constraints<F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize
>(
    local_values: &[P],
    next_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize,
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for i in 0..24*3 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_INPUT_OFFSET + i] -
            next_values[start_col + FP6_FORBENIUS_MAP_INPUT_OFFSET + i])
        );
    }
    yield_constr.constraint_transition(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP6_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP6_FORBENIUS_MAP_POW_OFFSET] -
        next_values[start_col + FP6_FORBENIUS_MAP_POW_OFFSET])
    );
    yield_constr.constraint(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP6_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP6_FORBENIUS_MAP_DIV_OFFSET] * FE::from_canonical_usize(6) +
        local_values[start_col + FP6_FORBENIUS_MAP_REM_OFFSET] -
        local_values[start_col + FP6_FORBENIUS_MAP_POW_OFFSET])
    );
    let bit0 = local_values[start_col + FP6_FORBENIUS_MAP_BIT0_OFFSET];
    let bit1 = local_values[start_col + FP6_FORBENIUS_MAP_BIT1_OFFSET];
    let bit2 = local_values[start_col + FP6_FORBENIUS_MAP_BIT2_OFFSET];
    yield_constr.constraint(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP6_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (bit0 +
        bit1 * FE::TWO +
        bit2 * FE::from_canonical_usize(4) -
        local_values[start_col + FP6_FORBENIUS_MAP_REM_OFFSET])
    );
    let forbenius_coefficients_1 = Fp6::forbenius_coefficients_1().iter().map(|fp2| fp2.get_u32_slice().concat().try_into().unwrap()).collect::<Vec<[u32; 24]>>();
    let forbenius_coefficients_2 = Fp6::forbenius_coefficients_2().iter().map(|fp2| fp2.get_u32_slice().concat().try_into().unwrap()).collect::<Vec<[u32; 24]>>();
    let y1 = (0..24).map(|i|
        (P::ONES - bit0) * (P::ONES - bit1) * FE::from_canonical_u32(forbenius_coefficients_1[0][i]) +
        (bit0) * (P::ONES - bit1) * FE::from_canonical_u32(forbenius_coefficients_1[1][i]) +
        (P::ONES - bit0) * (bit1) * FE::from_canonical_u32(forbenius_coefficients_1[2][i]) +
        (bit0) * (bit1) * FE::from_canonical_u32(forbenius_coefficients_1[3][i])
    ).collect::<Vec<P>>();
    let y2 = (0..24).map(|i|
        (P::ONES - bit0) * (P::ONES - bit1) * FE::from_canonical_u32(forbenius_coefficients_2[0][i]) +
        (bit0) * (P::ONES - bit1) * FE::from_canonical_u32(forbenius_coefficients_2[1][i]) +
        (P::ONES - bit0) * (bit1) * FE::from_canonical_u32(forbenius_coefficients_2[2][i]) +
        (bit0) * (bit1) * FE::from_canonical_u32(forbenius_coefficients_2[3][i])
    ).collect::<Vec<P>>();

    yield_constr.constraint(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP6_FORBENIUS_MAP_X_CALC_OFFSET + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP6_FORBENIUS_MAP_X_CALC_OFFSET + FP2_FORBENIUS_MAP_POW_OFFSET] -
        local_values[start_col + FP6_FORBENIUS_MAP_POW_OFFSET])
    );
    for i in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_X_CALC_OFFSET + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_X_CALC_OFFSET + FP2_FORBENIUS_MAP_INPUT_OFFSET + i] -
            local_values[start_col + FP6_FORBENIUS_MAP_INPUT_OFFSET + i])
        );
    }
    add_fp2_forbenius_map_constraints(local_values, next_values, yield_constr, start_col + FP6_FORBENIUS_MAP_X_CALC_OFFSET, bit_selector);

    yield_constr.constraint(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP6_FORBENIUS_MAP_T0_CALC_OFFSET + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP6_FORBENIUS_MAP_T0_CALC_OFFSET + FP2_FORBENIUS_MAP_POW_OFFSET] -
        local_values[start_col + FP6_FORBENIUS_MAP_POW_OFFSET])
    );
    for i in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_T0_CALC_OFFSET + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_T0_CALC_OFFSET + FP2_FORBENIUS_MAP_INPUT_OFFSET + i] -
            local_values[start_col + FP6_FORBENIUS_MAP_INPUT_OFFSET + i + 24])
        );
    }
    add_fp2_forbenius_map_constraints(local_values, next_values, yield_constr, start_col + FP6_FORBENIUS_MAP_T0_CALC_OFFSET, bit_selector);

    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_Y_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_Y_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i] -
            local_values[start_col + FP6_FORBENIUS_MAP_T0_CALC_OFFSET + FP2_FORBENIUS_MAP_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_Y_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_Y_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i + 12] -
            local_values[start_col + FP6_FORBENIUS_MAP_T0_CALC_OFFSET + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS + REDUCED_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_Y_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_Y_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i] -
            y1[i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_Y_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_Y_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i + 12] -
            y1[i + 12])
        );
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP6_FORBENIUS_MAP_Y_CALC_OFFSET, bit_selector);

    yield_constr.constraint(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP6_FORBENIUS_MAP_T1_CALC_OFFSET + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP6_FORBENIUS_MAP_T1_CALC_OFFSET + FP2_FORBENIUS_MAP_POW_OFFSET] -
        local_values[start_col + FP6_FORBENIUS_MAP_POW_OFFSET])
    );
    for i in 0..24 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_T1_CALC_OFFSET + FP2_FORBENIUS_MAP_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_T1_CALC_OFFSET + FP2_FORBENIUS_MAP_INPUT_OFFSET + i] -
            local_values[start_col + FP6_FORBENIUS_MAP_INPUT_OFFSET + i + 48])
        );
    }
    add_fp2_forbenius_map_constraints(local_values, next_values, yield_constr, start_col + FP6_FORBENIUS_MAP_T1_CALC_OFFSET, bit_selector);

    for i in 0..12 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_Z_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_Z_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i] -
            local_values[start_col + FP6_FORBENIUS_MAP_T1_CALC_OFFSET + FP2_FORBENIUS_MAP_INPUT_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_Z_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_Z_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + i + 12] -
            local_values[start_col + FP6_FORBENIUS_MAP_T1_CALC_OFFSET + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS + REDUCED_OFFSET + i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_Z_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_Z_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i] -
            y2[i])
        );
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP6_FORBENIUS_MAP_Z_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
            (local_values[start_col + FP6_FORBENIUS_MAP_Z_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + i + 12] -
            y2[i + 12])
        );
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP6_FORBENIUS_MAP_Z_CALC_OFFSET, bit_selector);
}

pub fn add_fp12_forbenius_map_constraints<F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize
>(
    local_values: &[P],
    next_values: &[P],
    yield_constr: &mut ConstraintConsumer<P>,
    start_col: usize,
    bit_selector: Option<P>,
) where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    for i in 0..24*3*2 {
        yield_constr.constraint_transition(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP12_FORBENIUS_MAP_SELECTOR_OFFSET] *
            (local_values[start_col + FP12_FORBENIUS_MAP_INPUT_OFFSET + i] -
            next_values[start_col + FP12_FORBENIUS_MAP_INPUT_OFFSET + i])
        );
    }
    yield_constr.constraint_transition(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP12_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP12_FORBENIUS_MAP_POW_OFFSET] -
        next_values[start_col + FP12_FORBENIUS_MAP_POW_OFFSET])
    );
    yield_constr.constraint(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP12_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP12_FORBENIUS_MAP_DIV_OFFSET] * FE::from_canonical_usize(12) +
        local_values[start_col + FP12_FORBENIUS_MAP_REM_OFFSET] -
        local_values[start_col + FP12_FORBENIUS_MAP_POW_OFFSET])
    );
    let bit0 = local_values[start_col + FP12_FORBENIUS_MAP_BIT0_OFFSET];
    let bit1 = local_values[start_col + FP12_FORBENIUS_MAP_BIT1_OFFSET];
    let bit2 = local_values[start_col + FP12_FORBENIUS_MAP_BIT2_OFFSET];
    let bit3 = local_values[start_col + FP12_FORBENIUS_MAP_BIT3_OFFSET];
    yield_constr.constraint(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP12_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (bit0 +
        bit1 * FE::TWO +
        bit2 * FE::from_canonical_usize(4) +
        bit3 * FE::from_canonical_usize(8) -
        local_values[start_col + FP12_FORBENIUS_MAP_REM_OFFSET])
    );
    let forbenius_coefficients = Fp12::forbenius_coefficients().iter().map(|fp2| fp2.get_u32_slice().concat().try_into().unwrap()).collect::<Vec<[u32; 24]>>();
    let y = (0..24).map(|i|
        (P::ONES - bit0) * (P::ONES - bit1) * (P::ONES - bit2) * FE::from_canonical_u32(forbenius_coefficients[0][i]) +
        (bit0) * (P::ONES - bit1) * (P::ONES - bit2) * FE::from_canonical_u32(forbenius_coefficients[1][i]) +
        (P::ONES - bit0) * (bit1) * (P::ONES - bit2) * FE::from_canonical_u32(forbenius_coefficients[2][i]) +
        (bit0) * (bit1) * (P::ONES - bit2) * FE::from_canonical_u32(forbenius_coefficients[3][i]) +
        (P::ONES - bit0) * (P::ONES - bit1) * (bit2) * FE::from_canonical_u32(forbenius_coefficients[4][i]) +
        (bit0) * (P::ONES - bit1) * (bit2) * FE::from_canonical_u32(forbenius_coefficients[5][i]) +
        (P::ONES - bit0) * (bit1) * (bit2) * FE::from_canonical_u32(forbenius_coefficients[6][i])
    ).collect::<Vec<P>>();
    yield_constr.constraint(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_POW_OFFSET] -
        local_values[start_col + FP12_FORBENIUS_MAP_POW_OFFSET])
    );
    for i in 0..24*3 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_SELECTOR_OFFSET] *
            (local_values[start_col + FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_INPUT_OFFSET + i] -
            local_values[start_col + FP12_FORBENIUS_MAP_INPUT_OFFSET + i])
        );
    }
    add_fp6_forbenius_map_constraints(local_values, next_values, yield_constr, start_col + FP12_FORBENIUS_MAP_R0_CALC_OFFSET, bit_selector);

    yield_constr.constraint(
        bit_selector.unwrap_or(P::ONES) *
        local_values[start_col + FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET + FP6_FORBENIUS_MAP_SELECTOR_OFFSET] *
        (local_values[start_col + FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET + FP6_FORBENIUS_MAP_POW_OFFSET] -
        local_values[start_col + FP12_FORBENIUS_MAP_POW_OFFSET])
    );
    for i in 0..24*3 {
        yield_constr.constraint(
            bit_selector.unwrap_or(P::ONES) *
            local_values[start_col + FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET + FP6_FORBENIUS_MAP_SELECTOR_OFFSET] *
            (local_values[start_col + FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET + FP6_FORBENIUS_MAP_INPUT_OFFSET + i] -
            local_values[start_col + FP12_FORBENIUS_MAP_INPUT_OFFSET + i + 24*3])
        );
    }
    add_fp6_forbenius_map_constraints(local_values, next_values, yield_constr, start_col + FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET, bit_selector);

    for i in 0..12 {
        for j in 0..2 {
            let offset = if j == 0 {
                FP6_FORBENIUS_MAP_X_CALC_OFFSET + FP2_FORBENIUS_MAP_INPUT_OFFSET
            } else {
                FP6_FORBENIUS_MAP_X_CALC_OFFSET + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS + REDUCED_OFFSET
            };
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_FORBENIUS_MAP_C0_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
                (local_values[start_col + FP12_FORBENIUS_MAP_C0_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + j*12 + i] -
                local_values[start_col + FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET + offset + i])
            );
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_FORBENIUS_MAP_C0_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
                (local_values[start_col + FP12_FORBENIUS_MAP_C0_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + j*12 + i] -
                y[j*12 + i])
            );
        }
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP12_FORBENIUS_MAP_C0_CALC_OFFSET, bit_selector);

    for i in 0..12 {
        for j in 0..2 {
            let offset = if j == 0 {
                FP6_FORBENIUS_MAP_Y_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET
            } else {
                FP6_FORBENIUS_MAP_Y_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET
            };
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_FORBENIUS_MAP_C1_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
                (local_values[start_col + FP12_FORBENIUS_MAP_C1_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + j*12 + i] -
                local_values[start_col + FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET + offset + i])
            );
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_FORBENIUS_MAP_C1_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
                (local_values[start_col + FP12_FORBENIUS_MAP_C1_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + j*12 + i] -
                y[j*12 + i])
            );
        }
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP12_FORBENIUS_MAP_C1_CALC_OFFSET, bit_selector);

    for i in 0..12 {
        for j in 0..2 {
            let offset = if j == 0 {
                FP6_FORBENIUS_MAP_Z_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET
            } else {
                FP6_FORBENIUS_MAP_Z_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET
            };
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_FORBENIUS_MAP_C2_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
                (local_values[start_col + FP12_FORBENIUS_MAP_C2_CALC_OFFSET + FP2_FP2_X_INPUT_OFFSET + j*12 + i] -
                local_values[start_col + FP12_FORBENIUS_MAP_C0C1C2_CALC_OFFSET + offset + i])
            );
            yield_constr.constraint(
                bit_selector.unwrap_or(P::ONES) *
                local_values[start_col + FP12_FORBENIUS_MAP_C2_CALC_OFFSET + FP2_FP2_SELECTOR_OFFSET] *
                (local_values[start_col + FP12_FORBENIUS_MAP_C2_CALC_OFFSET + FP2_FP2_Y_INPUT_OFFSET + j*12 + i] -
                y[j*12 + i])
            );
        }
    }
    add_fp2_mul_constraints(local_values, next_values, yield_constr, start_col + FP12_FORBENIUS_MAP_C2_CALC_OFFSET, bit_selector);
}
// Implement constraint generator
impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for ForbeniusMapStark<F, D> {
    type EvaluationFrame<FE, P, const D2: usize> = StarkFrame<P, P::Scalar, COLUMNS, PUBLIC_INPUTS>
    where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: &Self::EvaluationFrame<FE, P, D2>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let local_values = vars.get_local_values();
        let next_values = vars.get_next_values();
        let public_inputs = vars.get_public_inputs();

        // ----
        for i in 0..24*3*2 {
            yield_constr.constraint(
                local_values[FP12_FORBENIUS_MAP_INPUT_OFFSET + i] - public_inputs[PIS_INPUT_OFFSET + i]
            );
        }
        yield_constr.constraint(
            local_values[FP12_FORBENIUS_MAP_POW_OFFSET] - public_inputs[PIS_POW_OFFSET]
        );
        for i in 0..12 {
            for j in 0..12 {
                let offset = if j == 0 {
                    FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_X_CALC_OFFSET + FP2_FORBENIUS_MAP_INPUT_OFFSET
                } else if j == 1 {
                    FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_X_CALC_OFFSET + FP2_FORBENIUS_MAP_T0_CALC_OFFSET + FP_MULTIPLICATION_TOTAL_COLUMNS + REDUCED_OFFSET
                } else if j == 2 {
                    FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_Y_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET
                } else if j == 3 {
                    FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_Y_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET
                } else if j == 4 {
                    FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_Z_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET
                } else if j == 5 {
                    FP12_FORBENIUS_MAP_R0_CALC_OFFSET + FP6_FORBENIUS_MAP_Z_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET
                } else if j == 6 {
                    FP12_FORBENIUS_MAP_C0_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET
                } else if j == 7 {
                    FP12_FORBENIUS_MAP_C0_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET
                } else if j == 8 {
                    FP12_FORBENIUS_MAP_C1_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET
                } else if j == 9 {
                    FP12_FORBENIUS_MAP_C1_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET
                } else if j == 10 {
                    FP12_FORBENIUS_MAP_C2_CALC_OFFSET + Z1_REDUCE_OFFSET + REDUCED_OFFSET
                } else {
                    FP12_FORBENIUS_MAP_C2_CALC_OFFSET + Z2_REDUCE_OFFSET + REDUCED_OFFSET
                };
                yield_constr.constraint(
                    local_values[offset + i] - public_inputs[PIS_RES_OFFSET + j*12 + i]
                );
            }
        }
        add_fp12_forbenius_map_constraints(local_values, next_values, yield_constr, 0, None);
    }

    type EvaluationFrameTarget =
        StarkFrame<ExtensionTarget<D>, ExtensionTarget<D>, COLUMNS, PUBLIC_INPUTS>;

    fn eval_ext_circuit(
        &self,
        _builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        _vars: &Self::EvaluationFrameTarget,
        _yield_constr: &mut starky::constraint_consumer::RecursiveConstraintConsumer<F, D>,
    ) {
        todo!()
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::PUBLIC_INPUTS;
    use crate::calc_pairing_precomp::PairingPrecompStark;
    use plonky2::field::types::Field;
    use plonky2::{
        plonk::config::{GenericConfig, PoseidonGoldilocksConfig},
        util::timing::TimingTree,
    };
    use starky::stark::Stark;
    use starky::util::trace_rows_to_poly_values;
    use starky::{config::StarkConfig, prover::prove, verifier::verify_stark_proof};

    #[test]
    fn test_fp2_mul() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = PairingPrecompStark<F, D>;

        let config = StarkConfig::standard_fast_config();
        let mut stark = S::new(16);
        let s_ = stark.clone();
        let x: [u32; 12] = [
            1550366109, 1913070572, 760847606, 999580752, 3273422733, 182645169, 1634881460,
            1043400770, 1526865253, 1101868890, 3712845450, 132602617,
        ];
        let y: [u32; 12] = [
            3621225457, 1284733598, 2592173602, 2778433514, 3415298024, 3512038034, 2556930252,
            2289409521, 759431638, 3707643405, 216427024, 234777573,
        ];
        let z: [u32; 12] = [
            3621225457, 1284733598, 2592173602, 2778433514, 3415298024, 3512038034, 2556930252,
            2289409521, 759431638, 3707643405, 216427024, 234777573,
        ];
        stark.generate_trace([x, x], [y, y], [z, z]);
        let mut public_inputs = Vec::new();
        for e in x.iter().chain(x.iter()) {
            public_inputs.push(F::from_canonical_u32(e.clone()));
        }
        for e in y.iter().chain(y.iter()) {
            public_inputs.push(F::from_canonical_u32(e.clone()));
        }
        for e in z.iter().chain(z.iter()) {
            public_inputs.push(F::from_canonical_u32(e.clone()));
        }
        assert_eq!(public_inputs.len(), PUBLIC_INPUTS);
        println!("constraint_degree: {:?}", stark.constraint_degree());
        let trace_poly_values = trace_rows_to_poly_values(stark.trace.clone());
        let proof = prove::<F, C, S, D>(
            stark,
            &config,
            trace_poly_values,
            &public_inputs,
            &mut TimingTree::default(),
        );
        verify_stark_proof(s_, proof.unwrap(), &config).unwrap();
    }
}
