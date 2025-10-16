use std::ffi::{c_char, c_int, CStr};
use wasm_bindgen::prelude::*;

static mut GF256_MUL2: [u8; 256] = [0; 256];
static mut GF256_MUL3: [u8; 256] = [0; 256];

pub fn init_cipher() {
    for i in 0..256 {
        unsafe {
            GF256_MUL2[i] = gf256_mul(2, i as u8);
            GF256_MUL3[i] = gf256_mul(3, i as u8);
        }
    }
}

#[inline]
fn gf256_mul_fast(a: u8, b: u8) -> u8 {
    unsafe {
        match a {
            2 => GF256_MUL2[b as usize],
            3 => GF256_MUL3[b as usize],
            _ => gf256_mul(a, b),
        }
    }
}

fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a; }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 { a ^= 0x1B; }
        b >>= 1;
    }
    p
}

fn prng_block(state: &mut [u64; 32]) -> [u64; 16] {
    let mut working = [0u64; 16];
    working.copy_from_slice(&state[0..16]);

    for _ in 0..8 {
        qr(&mut working, 0, 4, 8, 12);
        qr(&mut working, 1, 5, 9, 13);
        qr(&mut working, 2, 6, 10, 14);
        qr(&mut working, 3, 7, 11, 15);
        qr(&mut working, 0, 5, 10, 15);
        qr(&mut working, 1, 6, 11, 12);
        qr(&mut working, 2, 7, 8, 13);
        qr(&mut working, 3, 4, 9, 14);
    }

    for i in 0..16 {
        working[i] = working[i].wrapping_add(state[i]);
    }

    for i in 0..32 {
        state[i] = state[i]
            .wrapping_add(working[i % 16].rotate_left((i as u32 % 13) + 5))
            .wrapping_add(0x9E3779B97F4A7C15u64 ^ (i as u64));
    }

    working
}

#[inline(always)]
fn qr(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = v[a].wrapping_add(v[b]);
    v[d] ^= v[a];
    v[d] = v[d].rotate_left(32);

    v[c] = v[c].wrapping_add(v[d]);
    v[b] ^= v[c];
    v[b] = v[b].rotate_left(24);

    v[a] = v[a].wrapping_add(v[b]);
    v[d] ^= v[a];
    v[d] = v[d].rotate_left(16);

    v[c] = v[c].wrapping_add(v[d]);
    v[b] ^= v[c];
    v[b] = v[b].rotate_left(63);
}

fn expand_key(key: &str) -> [u64; 32] {
    let kb = key.as_bytes();
    let mut out = [0u64; 32];
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15 ^ (kb.len() as u64).wrapping_mul(0xA5A5_A5A5_A5A5_A5A5);

    for (i, &b) in kb.iter().enumerate() {
        seed ^= (b as u64).wrapping_shl((i % 8) as u32 * 8);
        seed = seed.rotate_left(13).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn mix64(x: u64) -> u64 {
        let mut z = x;
        z ^= z >> 30;
        z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z ^= z >> 27;
        z = z.wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        z
    }

    for i in 0..32 {
        let v = seed
            .wrapping_add((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
            ^ (i as u64).rotate_left(17)
            ^ (kb.get(i % kb.len()).copied().unwrap_or(0) as u64).wrapping_mul(0xA5A5_A5A5_A5A5_A5A5);
        out[i] = mix64(v);
    }

    out
}

fn shift_mix_rows(state: &mut [u64; 16]) {
    // ShiftRows
    for row in 0..8 {
        let mut t = [0u8;16];
        for col in 0..16 { t[col] = ((state[col] >> (row*8)) & 0xFF) as u8; }
        let mut t2 = [0u8;16];
        for col in 0..16 { t2[col] = t[(col+row)%16]; }
        for col in 0..16 {
            state[col] &= !(0xFF << (row*8));
            state[col] |= (t2[col] as u64) << (row*8);
        }
    }
    // MixColumns
    for j in 0..4 {
        let mut col = [state[j], state[j+4], state[j+8], state[j+12]];
        mix_columns(&mut col);
        state[j]=col[0]; state[j+4]=col[1]; state[j+8]=col[2]; state[j+12]=col[3];
    }
}

fn mix_columns(col: &mut [u64;4]) {
    let mut res = [0u64;4];
    for byte_idx in 0..8 {
        let a = [
            ((col[0] >> (byte_idx*8)) & 0xFF) as u8,
            ((col[1] >> (byte_idx*8)) & 0xFF) as u8,
            ((col[2] >> (byte_idx*8)) & 0xFF) as u8,
            ((col[3] >> (byte_idx*8)) & 0xFF) as u8,
        ];
        let b = [
            gf256_mul_fast(2,a[0]) ^ gf256_mul_fast(3,a[1]) ^ a[2] ^ a[3],
            a[0] ^ gf256_mul_fast(2,a[1]) ^ gf256_mul_fast(3,a[2]) ^ a[3],
            a[0] ^ a[1] ^ gf256_mul_fast(2,a[2]) ^ gf256_mul_fast(3,a[3]),
            gf256_mul_fast(3,a[0]) ^ a[1] ^ a[2] ^ gf256_mul_fast(2,a[3]),
        ];
        for i in 0..4 { res[i] |= (b[i] as u64) << (byte_idx*8); }
    }
    *col = res;
}

pub fn anse2_encrypt(input: &[u8], key: &str) -> Vec<u8> {
    let mut state = [0u64;16];
    let kb = expand_key(key);

    for i in 0..16 {
        state[i] = if i<kb.len() { kb[i] } else { (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) };
    }
    let mut prng_state = [0u64;32];
    for i in 0..32 {
        prng_state[i] = if i<kb.len() { kb[i] } else { (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) };
    }

    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        let block_len = (input.len() - i).min(128);
        let prng_vals = prng_block(&mut prng_state);
        for j in 0..block_len {
            let idx = j % 16;
            let prng_byte = ((prng_vals[idx] >> ((j%8)*8)) & 0xFF) as u8;
            let cipher = input[i+j] ^ prng_byte;
            out.push(cipher);
            state[idx] ^= cipher as u64;
            state[(idx+5)%16] = state[(idx+5)%16].rotate_left(16) ^ (cipher as u64);
        }
        shift_mix_rows(&mut state);
        i += block_len;
    }

    out
}

pub fn anse2_decrypt(input: &[u8], key: &str) -> Vec<u8> {
    anse2_encrypt(input, key)
}


// c api

#[unsafe(no_mangle)]
pub extern "C" fn anse2_init_tables() {
    // initializing (init_cipher)
    init_cipher();
}

/// encrypt: allocating buffer and returns it from out_ptr and out_len.
/// caller needed to call anse2_free_buffer for freeing.
/// error codes:
/// 0 = ok
/// 1 = null pointer (input or output or key)
/// 2 = allocation failure
/// 3 = invalid utf8 in key
#[unsafe(no_mangle)]
pub extern "C" fn anse2_encrypt_c(
    input_ptr: *const u8,
    input_len: usize,
    key_ptr: *const c_char,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    // basic null checks
    if input_ptr.is_null() || key_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 1;
    }

    // convert input slice
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };

    // convert key c-string -> rust str
    let cstr = unsafe { CStr::from_ptr(key_ptr) };
    let key = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return 3,
    };

    // call rust encrypt
    let res = anse2_encrypt(input, key);

    // convert Vec<u8> -> leaked Box<[u8]> and return pointer+len
    // into_boxed_slice allows safe reconstruction later
    let mut boxed = res.into_boxed_slice();
    let len = boxed.len();
    let ptr_data = boxed.as_mut_ptr();
    // create fat ptr to slice and forget boxed so memory stays allocated
    let _slice_ptr = std::ptr::slice_from_raw_parts_mut(ptr_data, len);
    std::mem::forget(boxed);

    unsafe {
        *out_ptr = ptr_data;
        *out_len = len;
    }

    0
}

/// decrypt: allocating buffer and returns it from out_ptr and out_len. (It's just a same as encrypt)
#[unsafe(no_mangle)]
pub extern "C" fn anse2_decrypt_c(
    input_ptr: *const u8,
    input_len: usize,
    key_ptr: *const c_char,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> c_int {
    anse2_encrypt_c(input_ptr, input_len, key_ptr, out_ptr, out_len)
}

/// free buffer previously returned by encrypt/decrypt
#[unsafe(no_mangle)]
pub extern "C" fn anse2_free_buffer(buf_ptr: *mut u8, buf_len: usize) {
    if buf_ptr.is_null() || buf_len == 0 {
        return;
    }
    // reconstruct Box<[u8]> from raw parts and drop it so memory is freed
    unsafe {
        let slice_ptr = std::ptr::slice_from_raw_parts_mut(buf_ptr, buf_len);
        // safety this pointer must have been allocated by into_boxed_slice() above
        let _boxed: Box<[u8]> = Box::from_raw(slice_ptr);
        // when _boxed goes out of scope, memory is freed
    }
}

// wasm api
#[wasm_bindgen]
pub fn anse2_encrypt_wasm(input: &[u8], key: &str) -> Vec<u8> {
    anse2_encrypt(input, key)
}

#[wasm_bindgen]
pub fn anse2_decrypt_wasm(input: &[u8], key: &str) -> Vec<u8> {
    anse2_decrypt(input, key)
}

#[wasm_bindgen]
pub fn anse2_init_wasm() {
    init_cipher()
}