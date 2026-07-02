//! Argon2id (RFC 9106): the memory-hard password KDF, implemented from
//! the specification and verified against the RFC test vector.
//!
//! Only the hybrid Argon2id variant is exposed: data-independent
//! addressing for the first half of the first pass (side-channel
//! resistance where the password's influence is freshest), then
//! data-dependent addressing (GPU/ASIC resistance).

use crate::blake2b::blake2b;

const VERSION: u32 = 0x13;
const ARGON2ID: u32 = 2;
const BLOCK_WORDS: usize = 128; // 1 KiB blocks
const SYNC_POINTS: usize = 4; // slices per pass
const ADDRESSES_PER_BLOCK: usize = 128;

type Block = [u64; BLOCK_WORDS];

const ZERO_BLOCK: Block = [0u64; BLOCK_WORDS];

/// Derive `out` from a passphrase with Argon2id.
///
/// `memory_kib` is the memory cost in KiB (one block each; clamped up
/// to `8 * lanes`), `passes` the time cost, `lanes` the parallelism
/// parameter (computed sequentially here — the memory-hardness, which
/// is what matters for defense, is identical).
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    out: &mut [u8],
) {
    argon2id_full(password, salt, b"", b"", memory_kib, passes, lanes, out);
}

/// Argon2id with the optional secret (pepper) and associated data
/// inputs. Exposed within the crate for the RFC test vector.
#[allow(clippy::too_many_arguments)]
pub(crate) fn argon2id_full(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated: &[u8],
    memory_kib: u32,
    passes: u32,
    lanes: u32,
    out: &mut [u8],
) {
    assert!(lanes >= 1, "Argon2 needs at least one lane");
    assert!(passes >= 1, "Argon2 needs at least one pass");
    assert!(!out.is_empty(), "Argon2 output must not be empty");

    let lanes = lanes as usize;
    // m' = 4 * p * floor(m / 4p), with the RFC minimum of 8 blocks/lane.
    let memory_blocks = (memory_kib as usize).max(8 * lanes);
    let memory_blocks = (memory_blocks / (SYNC_POINTS * lanes)) * (SYNC_POINTS * lanes);
    let lane_length = memory_blocks / lanes; // q
    let segment_length = lane_length / SYNC_POINTS;

    // H0: the 64-byte seed binding every parameter and input.
    let mut h0_input = Vec::new();
    for word in [
        lanes as u32,
        out.len() as u32,
        memory_kib,
        passes,
        VERSION,
        ARGON2ID,
    ] {
        h0_input.extend_from_slice(&word.to_le_bytes());
    }
    for data in [password, salt, secret, associated] {
        h0_input.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h0_input.extend_from_slice(data);
    }
    let h0 = blake2b(64, &h0_input);

    // First two blocks of every lane come straight from H0.
    let mut memory: Vec<Block> = vec![ZERO_BLOCK; memory_blocks];
    for lane in 0..lanes {
        for col in 0..2 {
            let mut seed = h0.clone();
            seed.extend_from_slice(&(col as u32).to_le_bytes());
            seed.extend_from_slice(&(lane as u32).to_le_bytes());
            let mut bytes = [0u8; 1024];
            h_prime(&mut bytes, &seed);
            memory[lane * lane_length + col] = block_from_bytes(&bytes);
        }
    }

    for pass in 0..passes as usize {
        for slice in 0..SYNC_POINTS {
            for lane in 0..lanes {
                fill_segment(
                    &mut memory,
                    pass,
                    lane,
                    slice,
                    lanes,
                    lane_length,
                    segment_length,
                    passes,
                );
            }
        }
    }

    // Final block: XOR of every lane's last column, hashed to length.
    let mut final_block = memory[lane_length - 1];
    for lane in 1..lanes {
        for (acc, word) in final_block
            .iter_mut()
            .zip(memory[lane * lane_length + lane_length - 1])
        {
            *acc ^= word;
        }
    }
    let mut final_bytes = [0u8; 1024];
    for (chunk, word) in final_bytes.chunks_exact_mut(8).zip(final_block) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    h_prime(out, &final_bytes);
}

/// Fill one segment of one lane (RFC 9106 §3.2 steps 5-6).
#[allow(clippy::too_many_arguments)]
fn fill_segment(
    memory: &mut [Block],
    pass: usize,
    lane: usize,
    slice: usize,
    lanes: usize,
    lane_length: usize,
    segment_length: usize,
    passes: u32,
) {
    // Argon2id: data-independent addressing for the first two slices of
    // the first pass, data-dependent afterwards.
    let independent = pass == 0 && slice < 2;

    let mut address_block = ZERO_BLOCK;
    let mut input_block = ZERO_BLOCK;
    if independent {
        input_block[0] = pass as u64;
        input_block[1] = lane as u64;
        input_block[2] = slice as u64;
        input_block[3] = memory.len() as u64;
        input_block[4] = passes as u64;
        input_block[5] = ARGON2ID as u64;
        // input_block[6] is the counter, bumped by next_addresses.
    }

    let starting_index = if pass == 0 && slice == 0 {
        // Blocks 0 and 1 were seeded from H0; also prime the addresses.
        if independent {
            next_addresses(&mut address_block, &mut input_block);
        }
        2
    } else {
        0
    };

    for index in starting_index..segment_length {
        let column = slice * segment_length + index;
        let prev_column = if column == 0 {
            lane_length - 1
        } else {
            column - 1
        };
        let prev = memory[lane * lane_length + prev_column];

        let pseudo_rand = if independent {
            // A fresh address block every 128 blocks. The first-slice
            // case (starting_index == 2) was primed above and reaches
            // this condition next at index 128.
            if index % ADDRESSES_PER_BLOCK == 0 {
                next_addresses(&mut address_block, &mut input_block);
            }
            address_block[index % ADDRESSES_PER_BLOCK]
        } else {
            prev[0]
        };
        let j1 = pseudo_rand as u32 as u64;
        let j2 = (pseudo_rand >> 32) as usize;

        let ref_lane = if pass == 0 && slice == 0 {
            lane
        } else {
            j2 % lanes
        };
        let same_lane = ref_lane == lane;

        // Reference area size |W| (RFC 9106 §3.4.1.3).
        let reference_area = if pass == 0 {
            if same_lane {
                column - 1
            } else {
                slice * segment_length - usize::from(index == 0)
            }
        } else if same_lane {
            lane_length - segment_length + index - 1
        } else {
            lane_length - segment_length - usize::from(index == 0)
        };

        // Non-uniform mapping favoring recent blocks: zz = |W|-1-(|W|*x)>>32.
        let x = (j1 * j1) >> 32;
        let y = (reference_area as u64 * x) >> 32;
        let zz = reference_area - 1 - y as usize;
        let start = if pass == 0 {
            0
        } else {
            (slice + 1) * segment_length % lane_length
        };
        let ref_column = (start + zz) % lane_length;

        let reference = memory[ref_lane * lane_length + ref_column];
        let target = lane * lane_length + column;
        let mixed = compress(&prev, &reference);
        if pass == 0 {
            memory[target] = mixed;
        } else {
            for (acc, word) in memory[target].iter_mut().zip(mixed) {
                *acc ^= word;
            }
        }
    }
}

/// address_block = G(0, G(0, input_block)), bumping the counter first.
fn next_addresses(address_block: &mut Block, input_block: &mut Block) {
    input_block[6] += 1;
    let inner = compress(&ZERO_BLOCK, input_block);
    *address_block = compress(&ZERO_BLOCK, &inner);
}

/// The Argon2 compression function G (RFC 9106 §3.5): R = X ^ Y, the
/// BlaMka permutation P over R's rows then columns, output Z ^ R.
fn compress(x: &Block, y: &Block) -> Block {
    let mut r = [0u64; BLOCK_WORDS];
    for i in 0..BLOCK_WORDS {
        r[i] = x[i] ^ y[i];
    }
    let mut q = r;

    // Rows: eight stripes of 16 consecutive words.
    for row in 0..8 {
        let mut words: [u64; 16] = q[row * 16..row * 16 + 16].try_into().unwrap();
        permute(&mut words);
        q[row * 16..row * 16 + 16].copy_from_slice(&words);
    }
    // Columns: the 16-byte register (i, j) is words (16i + 2j, 16i + 2j + 1).
    for col in 0..8 {
        let mut words = [0u64; 16];
        for i in 0..8 {
            words[2 * i] = q[16 * i + 2 * col];
            words[2 * i + 1] = q[16 * i + 2 * col + 1];
        }
        permute(&mut words);
        for i in 0..8 {
            q[16 * i + 2 * col] = words[2 * i];
            q[16 * i + 2 * col + 1] = words[2 * i + 1];
        }
    }

    let mut out = [0u64; BLOCK_WORDS];
    for i in 0..BLOCK_WORDS {
        out[i] = q[i] ^ r[i];
    }
    out
}

/// The BlaMka permutation: a BLAKE2b round whose G mixes in a 32x32→64
/// multiplication for better resistance to hardware speedups.
fn permute(v: &mut [u64; 16]) {
    blamka(v, 0, 4, 8, 12);
    blamka(v, 1, 5, 9, 13);
    blamka(v, 2, 6, 10, 14);
    blamka(v, 3, 7, 11, 15);
    blamka(v, 0, 5, 10, 15);
    blamka(v, 1, 6, 11, 12);
    blamka(v, 2, 7, 8, 13);
    blamka(v, 3, 4, 9, 14);
}

#[inline(always)]
fn blamka(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    #[inline(always)]
    fn mix(x: u64, y: u64) -> u64 {
        let lo = (x as u32 as u64).wrapping_mul(y as u32 as u64);
        x.wrapping_add(y).wrapping_add(lo.wrapping_mul(2))
    }
    v[a] = mix(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = mix(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = mix(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = mix(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// The variable-length hash H' (RFC 9106 §3.3).
fn h_prime(out: &mut [u8], input: &[u8]) {
    let t = out.len();
    let mut prefixed = Vec::with_capacity(4 + input.len());
    prefixed.extend_from_slice(&(t as u32).to_le_bytes());
    prefixed.extend_from_slice(input);

    if t <= 64 {
        out.copy_from_slice(&blake2b(t, &prefixed));
        return;
    }
    let mut v = blake2b(64, &prefixed);
    out[..32].copy_from_slice(&v[..32]);
    let mut written = 32;
    while t - written > 64 {
        v = blake2b(64, &v);
        out[written..written + 32].copy_from_slice(&v[..32]);
        written += 32;
    }
    let tail = blake2b(t - written, &v);
    out[written..].copy_from_slice(&tail);
}

fn block_from_bytes(bytes: &[u8; 1024]) -> Block {
    let mut block = [0u64; BLOCK_WORDS];
    for (word, chunk) in block.iter_mut().zip(bytes.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::hex;

    #[test]
    fn rfc9106_argon2id_vector() {
        // RFC 9106 §5.3: Argon2id, m=32 KiB, t=3, p=4, 32-byte tag,
        // password 0x01*32, salt 0x02*16, secret 0x03*8, ad 0x04*12.
        let mut out = [0u8; 32];
        argon2id_full(
            &[0x01; 32],
            &[0x02; 16],
            &[0x03; 8],
            &[0x04; 12],
            32,
            3,
            4,
            &mut out,
        );
        assert_eq!(
            out.to_vec(),
            hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    #[test]
    fn deterministic_and_parameter_sensitive() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        argon2id(b"password", b"somesalt16bytes!", 32, 1, 1, &mut a);
        argon2id(b"password", b"somesalt16bytes!", 32, 1, 1, &mut b);
        assert_eq!(a, b);
        argon2id(b"password", b"somesalt16bytes!", 64, 1, 1, &mut b);
        assert_ne!(a, b);
        argon2id(b"password", b"somesalt16bytes!", 32, 2, 1, &mut b);
        assert_ne!(a, b);
        argon2id(b"passwore", b"somesalt16bytes!", 32, 1, 1, &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn h_prime_long_output_is_consistent() {
        // 1024-byte outputs (block seeding) must be stable and differ
        // from a plain BLAKE2b chain without the length prefix.
        let mut a = [0u8; 1024];
        let mut b = [0u8; 1024];
        h_prime(&mut a, b"seed");
        h_prime(&mut b, b"seed");
        assert_eq!(a.to_vec(), b.to_vec());
        let mut c = [0u8; 1024];
        h_prime(&mut c, b"seeD");
        assert_ne!(a.to_vec(), c.to_vec());
    }
}
