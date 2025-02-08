use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use bluesome_lib::database::*;
use bluesome_lib::types::*;
use bluesome_lib::processing::encryption::*;
use bluesome_lib::auth::key_derivation::*;
use hex_literal::hex;
use std::fs;

fn bench(c: &mut Criterion) {
    let nonce = generate_nonce();
    let nonce2 = generate_nonce();
    let salts = generate_salts();
    let ad = generate_ad();
    let plaint_text = String::from("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    let key : [u8;32] = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");

    // Param 
    let param = Param::create(nonce.clone(), ad.clone(), salts[0].clone(), salts[1].clone()); 

    // Secret
    
    create_db_tables("test.sqlite3", param.clone()).unwrap();

    c.bench_function("generate database", |b| b.iter(|| generate_db_name()));
    
    c.bench_function("generate table", |b| b.iter(||{ 
        fs::remove_file("test.sqlite3").unwrap();
        create_db_tables(black_box("test.sqlite3"), black_box(param.clone())).unwrap();
    }));

    
    /*c.bench_function("read secret", |b|{
        let secret = Secret::create(&key, param.ad.clone(), nonce2.clone(), String::from("test"), plaint_text.clone());
        b.iter(|| create_new_secret(black_box("test.sqlite3"), black_box(secret.clone())))
    }); */
}

criterion_group!(benches, bench);
criterion_main!(benches);
