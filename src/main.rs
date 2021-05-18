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

use aes_siv::aead::{Aead, NewAead};
use aes_siv::{Aes128SivAead, Key, Nonce};
use chrono::prelude::*;
use rand::Rng;
use std::path::Path;
use std::str;
use std::{convert::TryInto, time::SystemTime};
use std::{fs::File, io::Write};
use structopt::StructOpt;

use std::io::prelude::*;

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
        help = "password less than 32 characters for encryption or decryption"
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
    let mut i: i32 = 0;

    if number_of_files != file_names.len().try_into().unwrap() {
        println!("Number of file names paassed as -f is not equal to number passed in -n");
    } else {
        for file in file_names {
            //check if encrypt or decrypt
            if option == "e".to_string().as_ref() {
                i = i + 1;
                let readContent = std::fs::read(&file).unwrap();

                println!("Encrypting {}", &file);
                let pass32 = make32(password.clone());
                let password_bytes = pass32.as_bytes();
                //println!("{}", password_bytes.len());

                let encrypted_data = encrypt(&readContent, &password_bytes, &nounce)
                    .ok()
                    .unwrap();
                //let encrypted_string = str::from_utf8(&encrypted_data).unwrap();
                let utc = Utc::now().timestamp();
                let mut fileStem = Path::new(&file)
                    .file_stem()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();

                let mut localfile = file.clone().to_owned();
                fileStem.push_str(&utc.to_string());
                fileStem.push_str("e");
                fileStem.push_str(&i.to_string());
                // let fileExtension=Path::new(&file).extension().unwrap().to_str().unwrap().to_string();
                // fileStem.push_str(&fileExtension);
                println!("File name is {}", &fileStem);
                let mut file = File::create(&fileStem);
                match file {
                    Ok(file) => {
                        let mut finalfile = file;
                        finalfile.write_all(&encrypted_data).unwrap();
                    }
                    Err(err) => {
                        println!("{} Error Creating the file {}", &err, &localfile);
                        break;
                    }
                }
            } else {
                println!("Decrypting {}", &file);
                let pass32 = make32(password.clone());
                let password_bytes = pass32.as_bytes();
                //println!("{}", password_bytes.len());
                let mut readfile = File::open(&file).unwrap();
                // read the same file back into a Vec of bytes
                let mut buffer = Vec::<u8>::new();
                readfile.read_to_end(&mut buffer);
                let utc = Utc::now().timestamp();
                let mut fileStem = Path::new(&file)
                    .file_stem()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                fileStem.push_str(&utc.to_string());
                fileStem.push_str("d");

                let decrypted_data = decrypt(&buffer[..], &password_bytes, &nounce);
                let decryptedResult;
                match decrypted_data {
                    Ok(decrypted_data1) => decryptedResult = decrypted_data1,
                    Err(err) => {
                        println!("Password is not correct");
                        return;
                    }
                }
                //let fileContent=str::from_utf8(&decrypted_data).unwrap();
                let mut newfile = File::create(&fileStem).unwrap();
                newfile.write_all(&decryptedResult).unwrap();
                println!("File name after decryption is {}", &fileStem);
                println!("just change the file extension after decryption");
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
            localpass.push_str(&len.to_string());
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
