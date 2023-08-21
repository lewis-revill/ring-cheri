// Copyright 2021 Brian Smith.
// Portions Copyright (c) 2014, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */
// Adapted from the public domain, estream code by D. Bernstein.
// Adapted from the BoringSSL crypto/chacha/chacha.c.

use super::{Iv, Key, BLOCK_LEN};
use crate::c;

pub(super) fn GFp_ChaCha20_ctr32(
    out: *mut u8,
    in_: *const u8,
    in_len: c::size_t,
    key: &Key,
    first_iv: Iv
) {
    const SIGMA: [u32; 4] = [
        u32::from_le_bytes(*b"expa"),
        u32::from_le_bytes(*b"nd 3"),
        u32::from_le_bytes(*b"2-by"),
        u32::from_le_bytes(*b"te k"),
    ];

    let key = key.0;
    let first_iv = first_iv.into_bytes_less_safe();

    let mut state = [ SIGMA[0], SIGMA[1], SIGMA[2], SIGMA[3], key[0].into(), key[1].into(),
    key[2].into(), key[3].into(), key[4].into(), key[5].into(), key[6].into(), key[7].into(),
    first_iv[0].into(), first_iv[1].into(), first_iv[2].into(), first_iv[3].into(), ];

    let mut output = out;
    let mut input = in_;
    let mut len = in_len;
    let mut buf = [0u8; BLOCK_LEN];
    while len > 0 {
        chacha_core(&mut buf, &state);
        state[12] += 1;

        let todo = core::cmp::min(BLOCK_LEN, len);
        for (i, &b) in buf[..todo].iter().enumerate() {
            let input = unsafe { *input.add(i) };
            let b = input ^ b;
            unsafe { *output.add(i) = b };
        }

        len -= todo;
        input = unsafe { input.add(todo) };
        unsafe { output = output.add(todo) };
    }
}

// Performs 20 rounds of ChaCha on `input`, storing the result in `output`.
#[inline(always)]
fn chacha_core(output: &mut [u8; BLOCK_LEN], input: &State) {
    let mut x = *input;

    for _ in (0..20).step_by(2) {
        quarterround(&mut x, 0, 4, 8, 12);
        quarterround(&mut x, 1, 5, 9, 13);
        quarterround(&mut x, 2, 6, 10, 14);
        quarterround(&mut x, 3, 7, 11, 15);
        quarterround(&mut x, 0, 5, 10, 15);
        quarterround(&mut x, 1, 6, 11, 12);
        quarterround(&mut x, 2, 7, 8, 13);
        quarterround(&mut x, 3, 4, 9, 14);
    }

    for (x, input) in x.iter_mut().zip(input.iter()) {
        *x = x.wrapping_add(*input);
    }

    for (output, &x) in output.chunks_exact_mut(4).zip(x.iter()) {
        output[0] = u32::to_le_bytes(x)[0];
        output[1] = u32::to_le_bytes(x)[1];
        output[2] = u32::to_le_bytes(x)[2];
        output[3] = u32::to_le_bytes(x)[3];
    }
}

#[inline(always)]
fn quarterround(x: &mut State, a: usize, b: usize, c: usize, d: usize) {
    #[inline(always)]
    fn step(x: &mut State, a: usize, b: usize, c: usize, rotation: u32) {
        x[a] = x[a].wrapping_add(x[b]);
        x[c] = (x[c] ^ x[a]).rotate_left(rotation);
    }
    step(x, a, b, d, 16);
    step(x, c, d, b, 12);
    step(x, a, b, d, 8);
    step(x, c, d, b, 7);
}

type State = [u32; BLOCK_LEN];
