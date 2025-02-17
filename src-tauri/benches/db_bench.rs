use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use bluesome_lib::database::*;
use bluesome_lib::types::*;
use bluesome_lib::processing::encryption::*;
use bluesome_lib::auth::key_derivation::*;
use hex_literal::hex;
use std::fs;
//use bluesome_lib::utils::encode_to_hex;

fn bench(c: &mut Criterion) {
    let nonce = generate_nonce();
    let salts = generate_salts();
    let ad = generate_ad();
    let plaint_text = String::from("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    let key : [u8;32] = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");

    // Param decoded 
    let param = Param::create(nonce, ad, salts[0].clone(), salts[1].clone()); 
    // Param encoded
    let param_hex = ParamHex::encode(param.clone());

    // Secret nonce
    //let mut nonce_secret = Vec::new();

    //DB connection
    let mut db = DBManager::open("bench.sqlite3").unwrap();
    db.create_tables().unwrap();

    c.bench_function("generate database", |b| b.iter(|| generate_db_name()));
    
    c.bench_function("generate_table", |b| b.iter(||{ 
        let mut db_local = DBManager::open("bench_local.sqlite3").unwrap();
        db_local.create_tables().unwrap();
        fs::remove_file("bench_local.sqlite3").unwrap();
    }));


    c.bench_function("insert_data_param", |b| b.iter(|| db.insert_data_param(black_box(param_hex.clone()))));

    // create secret
    c.bench_function("insert_data_secret", |b| b.iter(|| {
        let nonce = generate_nonce();
        let secret = Secret::create(&key, nonce, param.ad.clone(), String::from("test"), plaint_text.clone());
        db.insert_data_secret(black_box(secret.clone())).unwrap()
    }));

    // read all secrets
    /*c.bench_function("read all secrets", |b| b.iter(|| read_all_secrets("test.sqlite3")));

    // read one secrets
    c.bench_function("read data", |b| b.iter(|| read_secret(black_box("test.sqlite3"), black_box(encode_to_hex(nonce_secret.clone()).as_str()))));

    // update data
    c.bench_function("update data", |b|{
        let secret = Secret::create(&key, param.ad.clone(), nonce_secret.clone(), String::from("test 1"), plaint_text);
        b.iter(|| update_secret(black_box("test.sqlite3"), black_box(secret.clone())))});

    c.bench_function("remove data", |b| b.iter(|| remove_secret(black_box("test.sqlite3"), black_box(encode_to_hex(nonce_secret.clone())))));

    //fs::remove_file("test.sqlite3").unwrap();
    //fs::remove_file("db_file.txt").unwrap();*/
}

criterion_group!(benches, bench);
criterion_main!(benches);
