//! Randomness, the keys of sealed secrets, TOTP and the small hashes the panel stores.
use ring::{aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305}, digest, hmac, rand::{SecureRandom, SystemRandom}};
use std::{fs::{self, OpenOptions}, io::{self, Write}, os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::Path};

pub fn random<const N: usize>() -> [u8; N] {
	let mut bytes = [0u8; N];
	SystemRandom::new().fill(&mut bytes).expect("system randomness");
	bytes
}

/// Fills a buffer of any length, in the shape the protocol crate asks of a random source.
pub fn fill(bytes: &mut [u8]) -> Result<(), veilway_proto::NoRandom> {SystemRandom::new().fill(bytes).map_err(|_| veilway_proto::NoRandom)}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {digest::digest(&digest::SHA256, bytes).as_ref().try_into().expect("32 bytes")}

pub fn equal(a: &[u8], b: &[u8]) -> bool {a.len() == b.len() && subtle::ConstantTimeEq::ct_eq(a, b).into()}

pub fn now() -> i64 {std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64)}

/// Writes a secret file that no one else can read, replacing an older one atomically.
pub fn write_private(path: &Path, content: &[u8], replace: bool) -> io::Result<()> {
	let temporary = path.with_extension("new");
	let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(if replace {&temporary} else {path})?;
	file.write_all(content)?;
	file.sync_all()?;
	if replace {fs::rename(&temporary, path)?}
	Ok(())
}

/// The three keys of the subscription format page, "Storing the token": no key serves two purposes.
pub struct Keys {lookup: [u8; 32], copy: [u8; 32], secret: [u8; 32]}

const TOKEN_LABEL: &[u8] = b"veilway v1 sub token";
const DEVICE_LABEL: &[u8] = b"veilway v1 sub device secret";
const COPY_LABEL: &[u8] = b"veilway v1 sub token copy";
const SECRET_LABEL: &[u8] = b"veilway v1 sub secret";

impl Keys {
	pub fn create(path: &Path) -> io::Result<Self> {
		let keys = Self {lookup: random(), copy: random(), secret: random()};
		write_private(path, &[keys.lookup, keys.copy, keys.secret].concat(), false)?;
		Ok(keys)
	}
	pub fn load(path: &Path) -> io::Result<Self> {
		let bytes = fs::read(path)?;
		if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the key file must be mode 600"))}
		if bytes.len() != 96 {return Err(io::Error::new(io::ErrorKind::InvalidData, "the key file is not 96 bytes"))}
		Ok(Self {lookup: bytes[..32].try_into().unwrap(), copy: bytes[32..64].try_into().unwrap(), secret: bytes[64..].try_into().unwrap()})
	}
	fn mac(&self, label: &[u8], bytes: &[u8]) -> [u8; 32] {
		let key = hmac::Key::new(hmac::HMAC_SHA256, &self.lookup);
		let mut context = hmac::Context::with_key(&key);
		context.update(label);
		context.update(bytes);
		context.sign().as_ref().try_into().expect("32 bytes")
	}
	pub fn token_lookup(&self, token: &[u8; 16]) -> [u8; 32] {self.mac(TOKEN_LABEL, token)}
	pub fn device_secret_hash(&self, secret: &[u8; 16]) -> [u8; 32] {self.mac(DEVICE_LABEL, secret)}
	fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Vec<u8> {
		let nonce: [u8; 12] = random();
		let mut buffer = plain.to_vec();
		LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("32 byte key")).seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut buffer).expect("sealing");
		[nonce.to_vec(), buffer].concat()
	}
	fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
		if sealed.len() < 12 + 16 {return None}
		let mut buffer = sealed[12..].to_vec();
		let plain = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).ok()?).open_in_place(Nonce::try_assume_unique_for_key(&sealed[..12]).ok()?, Aad::from(aad), &mut buffer).ok()?;
		Some(plain.to_vec())
	}
	pub fn seal_copy(&self, record: &[u8; 16], token: &[u8; 16]) -> Vec<u8> {Self::seal(&self.copy, &[COPY_LABEL, record].concat(), token)}
	pub fn open_copy(&self, record: &[u8; 16], sealed: &[u8]) -> Option<[u8; 16]> {Self::open(&self.copy, &[COPY_LABEL, record].concat(), sealed)?.try_into().ok()}
	pub fn seal_secret(&self, record: &[u8; 16], name: impl AsRef<[u8]>, plain: &[u8]) -> Vec<u8> {Self::seal(&self.secret, &[SECRET_LABEL, record, name.as_ref()].concat(), plain)}
	pub fn open_secret(&self, record: &[u8; 16], name: impl AsRef<[u8]>, sealed: &[u8]) -> Option<Vec<u8>> {Self::open(&self.secret, &[SECRET_LABEL, record, name.as_ref()].concat(), sealed)}
}

/// RFC 6238 with SHA-1, 30 seconds and 6 digits, the form every authenticator app takes.
pub fn totp_at(secret: &[u8], step: u64) -> u32 {
	let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret), &step.to_be_bytes());
	let tag = tag.as_ref();
	let at = (tag[19] & 0xf) as usize;
	u32::from_be_bytes([tag[at] & 0x7f, tag[at + 1], tag[at + 2], tag[at + 3]]) % 1_000_000
}

/// The step a code belongs to, one step either side of now allowed for a slow clock. The caller refuses a step that is not above the last one it accepted, so a code works once.
pub fn totp_check(secret: &[u8], code: &str, now: i64) -> Option<i64> {
	if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {return None}
	let step = now / 30;
	(step - 1..=step + 1).find(|candidate| equal(format!("{:06}", totp_at(secret, *candidate as u64)).as_bytes(), code.as_bytes()))
}
