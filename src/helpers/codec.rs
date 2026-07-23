// Apply ROT47 encoding/decoding to a byte buffer.
pub fn rot47(buf: &mut [u8]) {
    for b in buf {
        if (33..=126).contains(b) {
            *b = 33 + ((*b - 33 + 94 - 47) % 94);
        }
    }
}
