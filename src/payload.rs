use crate::syscall;

pub static PAYLOAD_ENC: [u8; 4] = [0x7F, 0x23, 0x80, 0xA9];

pub static PLAINTEXT: [u8; 4] = [0x48, 0x31, 0xC0, 0xC3]; // xor eax, eax; ret

const KEY: [u8; 8] = [0x37, 0x13, 0x42, 0x69, 0xF0, 0x0D, 0x42, 0x2A];

pub fn encrypt(buf: &mut [u8], key: &[u8]) {
    assert!(!key.is_empty(), "empty key");
    let mut k = key.to_vec();
    for (i, b) in buf.iter_mut().enumerate() {
        let j = i % k.len();
        let c = *b ^ k[j] ^ (i as u8);
        *b = c;
        k[j] = k[j].rotate_left(3) ^ c;
    }
}

pub fn decrypt(buf: &mut [u8], key: &[u8]) {
    assert!(!key.is_empty(), "empty key");
    let mut k = key.to_vec();
    for (i, b) in buf.iter_mut().enumerate() {
        let j = i % k.len();
        let c = *b;
        *b = c ^ k[j] ^ (i as u8);
        k[j] = k[j].rotate_left(3) ^ c;
    }
}

pub fn run() {
    let mut buf = PAYLOAD_ENC;
    decrypt(&mut buf, &KEY);
    match unsafe { syscall::exec(&buf) } {
        Ok(()) => println!("[+] payload executed and returned"),
        Err(e) => eprintln!("[!] payload failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_blob_matches_plaintext() {
        let mut buf = PAYLOAD_ENC;
        decrypt(&mut buf, &KEY);
        assert_eq!(buf, PLAINTEXT);
    }

    #[test]
    fn round_trip_arbitrary() {
        let original: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        let mut buf = original.clone();
        encrypt(&mut buf, &KEY);
        assert_ne!(buf, original, "ciphertext must differ from plaintext");
        decrypt(&mut buf, &KEY);
        assert_eq!(buf, original);
    }

    #[test]
    fn keystream_is_not_repeating() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        encrypt(&mut a, &KEY);
        encrypt(&mut b, &KEY);
        assert_eq!(a, b); // deterministic
        let mut c = [0u8; 16];
        c[8..].copy_from_slice(&a[..8]);
        encrypt(&mut c, &KEY);
        assert_ne!(&c[..8], &a[8..]); // position matters, not just value
    }
}
