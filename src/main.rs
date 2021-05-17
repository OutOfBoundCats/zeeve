use crypto::{
    aes::{self, KeySize},
    bcrypt::bcrypt,
    pbkdf2::pbkdf2_simple,
};
use crypto::{blockmodes, buffer, symmetriccipher};
use crypto::{
    buffer::{BufferResult, ReadBuffer, WriteBuffer},
    sha1::Sha1,
};
use crypto::{pbkdf2::pbkdf2, symmetriccipher::SynchronousStreamCipher};

use rand::Rng;
use std::convert::TryInto;
use std::path::Path;
use std::str;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "zeeve", about = "An example of zeeve encryptor usage.")]
struct Cli {
    #[structopt(
        short = "o",
        long = "option",
        help = "select either e (for encryption) or d (for decryption)"
    )]
    option: String,
    #[structopt(
        short = "p",
        long = "password",
        help = "password for encryption or decryption"
    )]
    password: String,
    #[structopt(
        short = "n",
        long = "number_of_files",
        help = "number of files you want to encrypt or decrypt"
    )]
    number_of_files: i32,
    #[structopt(short = "f", long = "file_names", help = "filenames")]
    filenames: Vec<String>,
}

fn main() {
    let nounce = "1111111111111111".as_bytes();
    let args = Cli::from_args();
    let file_names: Vec<String> = args.filenames;
    let number_of_files: i32 = args.number_of_files;
    let option: String = args.option;
    let password: String = args.password;

    if number_of_files != file_names.len().try_into().unwrap() {
        println!("Number of file names paassed as -f is not equal to number passed in -n");
    } else {
        for file in file_names {
            let content = std::fs::read_to_string(&file);
            let readContent;
            match content {
                Ok(content) => {
                    readContent = content;
                }
                Err(error) => {
                    println!("{} File could not be read please check if file exist and have correct permissions", &file);
                    break;
                }
            }
            //check if encrypt or decrypt
            if option == "e".to_string().as_ref() {
                println!("Encrypting {}", &file);
                let pass32 = make32(password.clone());
                let password_bytes = pass32.as_bytes();
                println!("{}", password_bytes.len());

                let encrypted_data = encrypt(readContent.as_bytes(), &password_bytes, &nounce)
                    .ok()
                    .unwrap();
                let decrypted_data = decrypt(&encrypted_data[..], &password_bytes, &nounce)
                    .ok()
                    .unwrap();
                let encrypted_string = str::from_utf8(&encrypted_data).unwrap();
                assert!(readContent.as_bytes() == &decrypted_data[..]);
                println!("readContent is {:?}", readContent.as_bytes());
                println!("decrypted is {:?}", decrypted_data);
            } else {
                println!("Decrypting {}", &file);
                let pass32 = make32(password.clone());
                let password_bytes = pass32.as_bytes();
                println!("{}", password_bytes.len());

                let encrypted_data = encrypt(readContent.as_bytes(), &password_bytes, &nounce)
                    .ok()
                    .unwrap();
                let decrypted_data = decrypt(&encrypted_data[..], &password_bytes, &nounce)
                    .ok()
                    .unwrap();
                assert!(readContent.as_bytes() == &decrypted_data[..]);
                println!("readContent is {:?}", readContent.as_bytes());
                println!("decrypted is {:?}", decrypted_data);
            }
        }
    }
}
fn make32(pass: String) -> String {
    let len = pass.len();
    let mut localpass = pass.clone();
    if len == 32 {
        return localpass.as_str().to_string();
    } else {
        let mut remain = 32 - len;
        while remain > 0 {
            localpass.push_str("1");
            remain = remain - 1;
        }
        return localpass.as_str().to_string();
    }
}

fn encrypt(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

fn decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}
