OCSP-x509
=========

Parsing and building of OCSP requests and responses in pure Rust.

This is an experimental, modified version of RustCrypto's x509-ocsp library. It is used as a temporary replacement
until that crate is released.

[https://github.com/RustCrypto/formats](https://github.com/RustCrypto/formats)

## OCSP Request Building

```rust
use der::Decode;
use ocsp_x509::{builder::OcspRequestBuilder, ext::Nonce, Request, Version};
use sha1::Sha1;
use std::{fs, io::Read};
use x509_cert::certificate::Certificate;

let mut f = fs::File::open("testdata/digicert-ca.der").expect("error opening file");
let mut data = Vec::new();
f.read_to_end(&mut data).expect("error reading file");
let issuer = Certificate::from_der(&data).expect("error formatting certificate");

let mut f = fs::File::open("testdata/amazon-crt.der").expect("error opening file");
let mut data = Vec::new();
f.read_to_end(&mut data).expect("error reading file");
let cert = Certificate::from_der(&data).expect("error formatting certificate");

let mut rng = rand::thread_rng();

let serial_number = &cert.tbs_certificate.serial_number;
let req = OcspRequestBuilder::new(Version::V1)
    .with_request(
        Request::from_issuer::<Sha1>(&issuer, serial_number.clone(), None)
            .expect("failed to build Request"),
    )
    .with_extension(Nonce::generate(&mut rng, 32))
    .expect("failed to build extension")
    .build();
```

## OCSP Responses

```rust
use der::Decode;
use ocsp_x509::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus};
use std::{fs, io::Read};
use x509_cert::{certificate::Certificate, serial_number::SerialNumber};

let mut f = fs::File::open("testdata/amazon-crt.der").expect("error opening file");
let mut data = Vec::new();
f.read_to_end(&mut data).expect("error reading file");
let cert = Certificate::from_der(&data).expect("error formatting certificate");
let serial = &cert.tbs_certificate.serial_number;

let mut f = fs::File::open("testdata/ocsp-amazon-resp.der").expect("error opening file");
let mut data = Vec::new();
f.read_to_end(&mut data).expect("error reading file");
let res = OcspResponse::from_der(&data).expect("error loading OCSP response");

match res.response_status {
    OcspResponseStatus::Successful => {
        let response_bytes = &res.response_bytes.expect("no response data");
        let basic_response = BasicOcspResponse::from_der(&response_bytes.response.as_bytes())
            .expect("error encoding response bytes");
        let mut filter = basic_response
            .tbs_response_data
            .responses
            .iter()
            .filter(|res| &res.cert_id.serial_number == serial)
            .map(|res| &res.cert_status);
        match filter.next() {
            Some(CertStatus::Good(_)) => { /* certificate is good */ }
            Some(_) => panic!("certificate is not valid"),
            None => panic!("serial not in OCSP response"),
        }
    },
    _ => panic!("OCSP response failed"),
}
```

## OCSP Response Building

```rust
use der::{asn1::GeneralizedTime, Decode};
use ocsp_x509::{
    builder::BasicOcspResponseBuilder, OcspResponse, SingleResponse, ResponderId,
    Version,
};
use rsa::{
    pkcs1v15::SigningKey,
    pkcs8::DecodePrivateKey,
    RsaPrivateKey,
};
use sha1::Sha1;
use sha2::Sha256;
use std::{fs, io::Read, time::Duration};
use x509_cert::{
    certificate::Certificate,
    crl::CertificateList,
    serial_number::SerialNumber,
    time::Time,
};

let mut f = fs::File::open("testdata/rsa2048-sha256-key.der").expect("error opening file");
let mut data = Vec::new();
f.read_to_end(&mut data).expect("error reading file");
let signing_key =
    RsaPrivateKey::from_pkcs8_der(&data).expect("error formatting signing key");
let signing_key = SigningKey::<Sha256>::new_with_prefix(signing_key);

let mut f = fs::File::open("testdata/rsa2048-sha256-crt.der").expect("error opening file");
let mut data = Vec::new();
f.read_to_end(&mut data).expect("error reading file");
let public_cert = Certificate::from_der(&data).expect("error formatting signing cert");

let mut f = fs::File::open("testdata/GoodCACert.der").expect("error opening file");
let mut data = Vec::new();
f.read_to_end(&mut data).expect("error reading file");
let issuer = Certificate::from_der(&data).expect("error formatting issuer");

let mut f = fs::File::open("testdata/GoodCACRL.crl").expect("error opening file");
let mut data = Vec::new();
f.read_to_end(&mut data).expect("error reading file");
let crl = CertificateList::from_der(&data).expect("error formatting CRL");

// Build response
let res = OcspResponse::successful(
    BasicOcspResponseBuilder::new(
        Version::V1,
        ResponderId::ByName(public_cert.tbs_certificate.subject.clone()),
        GeneralizedTime::from_unix_duration(Duration::from_secs(0))
            .expect("error making produced_at"),
    )
    .with_single_response(
        SingleResponse::from_crl::<Sha1>(
            &crl,
            &issuer,
            SerialNumber::new(&[0xFu8]).expect("error making serial number"),
            match &crl.tbs_cert_list.this_update {
                Time::UtcTime(t) => GeneralizedTime::from_date_time(t.to_date_time()),
                Time::GeneralTime(t) => t.clone(),
            },
            match &crl.tbs_cert_list.next_update {
                Some(time) => match time {
                    Time::UtcTime(t) => Some(GeneralizedTime::from_date_time(t.to_date_time())),
                    Time::GeneralTime(t) => Some(t.clone()),
                },
                None => None,
            },
            None,
        )
        .expect("error making single response"),
    )
    .build_and_sign(&signing_key, Some(Vec::from([public_cert.clone()])))
    .expect("error signing response"),
)
.expect("error encoding ocsp response");
```

## License

Per [RustCrypto](https://github.com/RustCrypto/formats), licensed under:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

