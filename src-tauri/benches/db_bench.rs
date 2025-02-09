use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use bluesome_lib::database::*;
use bluesome_lib::types::*;
use bluesome_lib::processing::encryption::*;
use bluesome_lib::auth::key_derivation::*;
use hex_literal::hex;
use std::fs;
use bluesome_lib::utils::{encode_to_hex};

//this function create an array of nonce
/*fn generate_nonces() -> Vec<Vec<u8>>{
    let mut array_nonce = Vec::new();
    for _ in 0..=2 {
        let nonce = generate_nonce();
        array_nonce.push(nonce);
    }
    array_nonce
}*/

fn bench(c: &mut Criterion) {
    let nonce = generate_nonce();
    let salts = generate_salts();
    let ad = generate_ad();
    let plaint_text = String::from("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    let key : [u8;32] = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");

    // Param 
    let param = Param::create(nonce, ad, salts[0].clone(), salts[1].clone()); 

    // Secret
    let mut nonce_secret = Vec::new();
    create_db_tables("test.sqlite3", param.clone()).unwrap();

    c.bench_function("generate database", |b| b.iter(|| generate_db_name()));
    
    c.bench_function("generate table", |b| b.iter(||{ 
        fs::remove_file("test.sqlite3").unwrap();
        create_db_tables(black_box("test.sqlite3"), black_box(param.clone())).unwrap();
    }));

    //Benchmark group
    // create secret
    c.bench_function("create secret", |b| b.iter(|| {
            let n = generate_nonce();
            nonce_secret = n.clone();
            let secret = Secret::create(&key, param.ad.clone(), n.clone(), String::from("test"), plaint_text.clone());
            create_new_secret(black_box("test.sqlite3"), black_box(secret.clone()))
        }));

    // read all secrets
    c.bench_function("read all secrets", |b| b.iter(|| read_all_secrets("test.sqlite3")));

    // read one secrets
    c.bench_function("read data", |b| b.iter(|| read_secret(black_box("test.sqlite3"), black_box(encode_to_hex(nonce_secret.clone()).as_str()))));

    // update data
    c.bench_function("update data", |b|{
        let secret = Secret::create(&key, param.ad.clone(), nonce_secret.clone(), String::from("test 1"), plaint_text.clone());
        b.iter(|| update_secret(black_box("test.sqlite3"), black_box(secret.clone())))});

    c.bench_function("remove data", |b| b.iter(|| remove_secret(black_box("test.sqlite3"), black_box(encode_to_hex(nonce_secret.clone())))));

    fs::remove_file("test.sqlite3").unwrap();
    fs::remove_file("db_file.txt").unwrap();
}

criterion_group!(benches, bench);
criterion_main!(benches);
