use crypto::{
    aes::{self, KeySize},
    bcrypt::bcrypt,
    hmac::Hmac,
    pbkdf2::pbkdf2_simple,
};
use crypto::{blockmodes, buffer, symmetriccipher};
use crypto::{
    buffer::{BufferResult, ReadBuffer, WriteBuffer},
    sha1::Sha1,
};
use crypto::{pbkdf2::pbkdf2, symmetriccipher::SynchronousStreamCipher};

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
    //salt
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
                let readContent;
                match std::fs::read(&file) {
                    Ok(res) => readContent = res,
                    Err(_) => {
                        println!("Cannot read the file {}", &file);
                        continue;
                    }
                }

                let mut mac = Hmac::new(Sha1::new(), &password.as_bytes());

                let mut dk = [0u8; 32];

                pbkdf2(&mut mac, &nounce, 100, &mut dk);

                println!("Encrypting {}", &file);

                //println!("{}", &dk.len());

                let encrypted_data = encrypt(&readContent, &dk[0..32], &nounce).ok().unwrap();
                match write_file(&'e', &encrypted_data, &file.as_str()) {
                    Ok(res) => {
                        println!("{}", &res);
                    }
                    Err(err) => {
                        println!("{}", &err)
                    }
                }
            } else {
                println!("Decrypting {}", &file);

                let readContent;
                match std::fs::read(&file) {
                    Ok(res) => readContent = res,
                    Err(_) => {
                        println!("Cannot read the file {}", &file);
                        continue;
                    }
                }

                let mut mac = Hmac::new(Sha1::new(), &password.as_bytes());

                let mut dk = [0u8; 32];

                pbkdf2(&mut mac, &nounce, 100, &mut dk);

                let decrypted_data = decrypt(&readContent, &dk[0..32], &nounce);
                let decryptedResult;
                match decrypted_data {
                    Ok(decrypted_data1) => decryptedResult = decrypted_data1,
                    Err(err) => {
                        println!("Password is not correct");
                        return;
                    }
                }

                match write_file(&'d', &decryptedResult, &file.as_str()) {
                    Ok(res) => {
                        println!("{}", &res);
                    }
                    Err(err) => {
                        println!("{}", &err)
                    }
                }
                //println!("File name after decryption is {}", &fileStem);
                println!(
                    "just change the file extension after decryption if it was not set earlier \n"
                );
            }
        }
    }
}

fn write_file(flag: &char, input: &[u8], filename: &str) -> Result<String, &'static str> {
    //check if file laready exist
    let mut status;
    match std::fs::read(&filename) {
        Ok(file) => status = "exist",
        Err(err) => return Err("file does not exist"),
    }
    //get part before extension
    let mut fileStem = Path::new(&filename)
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    //get extension
    let mut file_extension: String = "".to_string();
    match Path::new(&filename).extension() {
        Some(fileResult) => file_extension = fileResult.to_str().unwrap().to_string(),
        None => {
            file_extension = "".to_string();
        }
    }
    //get final file name

    if *flag == 'e' {
        fileStem.push_str("_E");
    } else {
        fileStem.push_str("_D");
    }
    if (file_extension != "".to_string()) {
        fileStem.push_str(".");
        fileStem.push_str(&file_extension);
    }
    //check if file name already there
    while Path::new(&fileStem).exists() {
        //println!("file already there");
        let mut newStem = Path::new(&fileStem)
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        newStem.push_str("_cp");
        let mut new_file_extension: String = "".to_string();
        match Path::new(&fileStem).extension() {
            Some(newfileResult) => {
                new_file_extension = newfileResult.to_str().unwrap().to_string();
                newStem.push_str(".");
                newStem.push_str(&new_file_extension);
            }
            None => {
                file_extension = "".to_string();
            }
        }

        fileStem = newStem;
    }

    //create file with the name
    let mut newfile;

    match File::create(&fileStem) {
        Ok(fileResult) => newfile = fileResult,
        Err(_) => return Err("error creating file"),
    }
    //write to file
    match newfile.write_all(input) {
        Ok(good) => {
            let returnString = format!("{} file created successfully ", &fileStem);
            return Ok(returnString);
        }
        Err(_) => return Err("error writing to file"),
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
