use crate::vrm::DecomposedRegexConfig;
use crate::EMAIL_VERIFY_CONFIG_ENV;
use crate::{default_config_params, DefaultEmailVerifyPublicInput};
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{verify_proof, Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_base::halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_base::halo2_proofs::poly::VerificationStrategy;
use halo2_base::halo2_proofs::SerdeFormat;
use itertools::Itertools;
use rand::rngs::OsRng;
use rand::thread_rng;
use snark_verifier_sdk::halo2::{gen_proof_shplonk, PoseidonTranscript};
use snark_verifier_sdk::NativeLoader;
use snark_verifier_sdk::{gen_pk, CircuitExt};
use std::env::set_var;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

// /// The number of limbs of the accumulator in the aggregation circuit.
// pub const NUM_ACC_INSTANCES: usize = 4 * LIMBS;
// /// The name of env variable for the path to the configuration json of the aggregation circuit.
// pub const VERIFY_CONFIG_KEY: &'static str = "VERIFY_CONFIG";

/// Generate SRS parameters.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `k` - the SRS size.
pub fn gen_params(params_path: &str, k: u32) -> Result<(), Error> {
    let rng = thread_rng();
    let params = ParamsKZG::<Bn256>::setup(k, rng);
    let f = File::create(params_path).unwrap();
    let mut writer = BufWriter::new(f);
    params.write(&mut writer).unwrap();
    writer.flush().unwrap();
    Ok(())
}

/// Reduce the size of the given SRS parameters.
///
/// # Arguments
/// * `original_params_path` - a file path of the original SRS parameters.
/// * `new_params_path` - a file path of the new SRS parameters.
/// * `k` - the reduced SRS size.
pub fn downsize_params(original_params_path: &str, new_params_path: &str, k: u32) -> Result<(), Error> {
    let f = File::open(Path::new(original_params_path)).unwrap();
    let mut reader = BufReader::new(f);
    let mut params = ParamsKZG::<Bn256>::read(&mut reader).unwrap();
    params.downsize(k);
    let f = File::create(new_params_path).unwrap();
    let mut writer = BufWriter::new(f);
    params.write(&mut writer).unwrap();
    writer.flush().unwrap();
    Ok(())
}

/// Generate proving and verifying keys for the email verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `pk_path` - a file path of the output proving key.
/// * `vk_path` - a file path of the output verifying key.
/// * `circuit` - an email verification circuit.
pub fn gen_keys<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, pk_path: &str, vk_path: &str, circuit: C) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);

    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = default_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let pk = gen_pk::<C>(&params, &circuit, None);
    println!("app pk generated");
    {
        let f = File::create(pk_path).unwrap();
        let mut writer = BufWriter::new(f);
        pk.write(&mut writer, SerdeFormat::RawBytesUnchecked).unwrap();
        writer.flush().unwrap();
    }

    let vk = pk.get_vk();
    {
        let f = File::create(vk_path).unwrap();
        let mut writer = BufWriter::new(f);
        vk.write(&mut writer, SerdeFormat::RawBytesUnchecked).unwrap();
        writer.flush().unwrap();
    }
    Ok(())
}

/// Generate a proof for the email verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `pk_path` - a file path of the proving key.
/// * `proof_path` - a file path of the output proof.
/// * `circuit` - an email verification circuit.
pub fn prove<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, pk_path: &str, proof_path: &str, circuit: C) -> Result<(), Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let mut params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let app_config = default_config_params();
    if params.k() > app_config.degree {
        params.downsize(app_config.degree);
    }
    let pk = {
        let f = File::open(Path::new(pk_path)).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    // let (circuit, headerhash, public_key_n, header_substrs, body_substrs) = gen_circuit_from_email_path(email_path).await;
    let instances = circuit.instances();
    let proof = gen_proof_shplonk(&params, &pk, circuit, instances, &mut OsRng, None);
    {
        let f = File::create(proof_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&proof).unwrap();
        writer.flush().unwrap();
    };
    Ok(())
}

/// Verify a proof for the email verification circuit.
///
/// # Arguments
/// * `params_path` - a file path of the SRS parameters.
/// * `circuit_config_path` - a file path of the configuration of the email verification circuit.
/// * `vk_path` - a file path of the verifying key.
/// * `proof_path` - a file path of the proof.
/// * `public_input_path` - a file path of the public input.
/// # Return values
/// Return `true` if the proof is valid, otherwise `false`.
pub fn verify<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, vk_path: &str, proof_path: &str, public_input_path: &str) -> Result<bool, Error> {
    let proof = {
        let mut f = File::open(&proof_path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    };
    verify_util::<C>(params_path, circuit_config_path, vk_path, proof, public_input_path)
}

fn verify_util<C: CircuitExt<Fr>>(params_path: &str, circuit_config_path: &str, vk_path: &str, proof: Vec<u8>, public_input_path: &str) -> Result<bool, Error> {
    set_var(EMAIL_VERIFY_CONFIG_ENV, circuit_config_path);
    let params = {
        let f = File::open(Path::new(params_path)).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(Path::new(vk_path)).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, C>(&mut reader, SerdeFormat::RawBytesUnchecked).unwrap()
    };
    let public_input = serde_json::from_reader::<_, DefaultEmailVerifyPublicInput>(File::open(public_input_path).unwrap()).unwrap();
    let instances = public_input.instances::<Fr>();
    let result = {
        let mut transcript_read = PoseidonTranscript::<NativeLoader, &[u8]>::new(&proof);
        VerificationStrategy::<_, VerifierSHPLONK<Bn256>>::finalize(verify_proof::<_, VerifierSHPLONK<Bn256>, _, _, _>(
            params.verifier_params(),
            &vk,
            AccumulatorStrategy::new(params.verifier_params()),
            &[&[instances.as_slice()]],
            &mut transcript_read,
        )?)
    };
    Ok(result)
}

/// Generate regex-definition text files from the given decomposed regex json file.
///
/// # Arguments
/// * `decomposed_regex_config_path` - a file path pf the decomposed regex json.
/// * `regex_dir_path` - a directory path in which the output text files are stored.
/// * `regex_files_prefix` - a prefix used for the output text files.
pub fn gen_regex_files(decomposed_regex_config_path: &str, regex_dir_path: &str, regex_files_prefix: &str) -> Result<(), Error> {
    let decomposed_regex_config = serde_json::from_reader::<File, DecomposedRegexConfig>(File::open(decomposed_regex_config_path).unwrap()).unwrap();
    let regex_dir_path = PathBuf::new().join(regex_dir_path);
    let allstr_file_path = regex_dir_path.join(format!("{}_allstr.txt", regex_files_prefix));
    let mut num_public_parts = 0usize;
    for part in decomposed_regex_config.parts.iter() {
        if part.is_public {
            num_public_parts += 1;
        }
    }
    let substr_file_pathes = (0..num_public_parts)
        .map(|idx| regex_dir_path.join(format!("{}_substr_{}.txt", regex_files_prefix, idx)))
        .collect_vec();
    decomposed_regex_config
        .gen_regex_files(&allstr_file_path, &substr_file_pathes)
        .expect("fail to generate regex files");
    Ok(())
}
