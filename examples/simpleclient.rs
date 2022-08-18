use std::process::{Command, Stdio};
/// This is the simplest possible client using rustls that does something useful:
/// it accepts the default configuration, loads some root certs, and then starts a dtls echo server
/// based on the openssl s_server command that echos back all messages.
///
/// It makes use of rustls::Stream to treat the underlying TLS connection as a basic
/// bi-directional stream -- the underlying IO is performed transparently.
///
/// Note that `unwrap()` is used to deal with networking errors; this is not something
/// that is sensible outside of example code.
use std::sync::{Arc, atomic};

use std::convert::TryInto;
use std::io::{stdout, Read, Write, BufReader, BufRead};
use std::net::TcpStream;
use std::thread;

use dustls::{OwnedTrustAnchor, RootCertStore};
use rustls::RootCertStore;



fn main() {
    /// Create Certs
    Command::new("openssl").args(["ecparam" ,"-out key.pem","-name prime256v1", "-genkey"]).output();
    Command::new("openssl").args(["req" ,"-new", "-sha256 ", "-key key.pem", "-out server.csr"]).output();
    Command::new("openssl").args(["x509" ,"-req", "-days 365 ", "-in server.csr", "-signkey key.pem", "-out cert.pem"]).output();
    // For use with dustls, use rustls-pem to load pem certs and keys.
    Command::new("openssl").args(["x509" , "-outform DER", "-in key.pem", "-out key.der"]).output();
    Command::new("openssl").args(["x509" , "-outform DER", "-in cert.pem", "-out cert.der"]).output();



    let config = dustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let run = atomic::AtomicBool::new(true);
    let start = atomic::AtomicBool::new(false);
    let handle = thread::spawn(|| openssl_thread(start, run));

    let mut wait= 0;
    loop {
        if start.load(Ordering::Relaxed) == true {
            break;
        } else {
            match handle {
                Ok(x) => {
                    if wait <=3 {
                        thread::sleep(std::time::Duration::from_secs(1))
                    } else {
                        exit()
                    }
                }
                Err(x) => {
                    if wait <=3 {
                        thread::sleep(std::time::Duration::from_secs(1))
                    } else {
                        exit()
                    }
                }
            }

        }
    }



    let server_name = "localhost".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("localhost:4444").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: google.com\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}


fn openssl_thread(started: atomic::AtomicBool, run : atomic::AtomicBool) -> Result<(), String>{
    let cmd = Command::new("openssl").args(["-cert cert.pem", "-key key.pem", "-dtls1_2", "-accept 4444"]).stdout(Stdio::piped());

    let child = cmd.spawn().map_err(|e| e.to_string())?;
    let stdout = child.stdout.ok_or_else(|| "Could not capture standard output.".into())?;

    let reader = BufReader::new(stdout);

    let mut iter = reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| line.find("usb").is_some());
    let stdin = child.stdin.as_mut().ok_or_else(|| "Could not acquire standard input.".into())?;
    started.store(true, atomic::Ordering::Relaxed);
    loop {
        match iter.next() {
            Some(line)  => {
            write!(stdin, "{}", line).map_err(|e| e.to_string())?
            }
        _ => {if run.load(atomic::Ordering::Relaxed) == false {break} else { continue} }
        }
    }



    Ok(())

}