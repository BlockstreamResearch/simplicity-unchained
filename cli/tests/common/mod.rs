use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

pub struct SecretFile(pub PathBuf);

impl SecretFile {
    pub fn new(secret: [u8; 32]) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::current_dir().unwrap().join(format!(
            ".policy-test-key-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).unwrap();
        file.write_all(hex::encode(secret).as_bytes()).unwrap();
        Self(path)
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        fs::remove_file(&self.0).unwrap();
    }
}
