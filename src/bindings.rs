#[no_mangle]
pub extern "C" fn rust_function_add(arg1: i32, arg2: i32) -> i32 {
    arg1 + arg2
}

use crate::{
    CSCurve,
    KeygenOutput,
    protocol::Protocol,
    participants::ParticipantList,
    protocol::{InitializationError, Participant, internal::{Context, make_protocol}},
};
use crate::keyshare::do_keygen;
use k256::Secp256k1;

type ConcreteCurve = Secp256k1;

#[repr(C)]
pub struct CParticipant {
    id: u32,
}

#[repr(C)]
pub struct CKeygenOutput {
    private_share: [u8; 32],
    public_key: [u8; 65],
}

#[repr(C)]
pub enum CInitializationError {
    BadParameters,
    // Add other error variants as needed
}

#[no_mangle]
pub extern "C" fn c_keygen(
    participants: *const CParticipant,
    participants_len: usize,
    me: CParticipant,
    threshold: usize,
    output: *mut CKeygenOutput,
) -> CInitializationError {
    let participants_slice = unsafe { std::slice::from_raw_parts(participants, participants_len) };
    
    let rust_participants: Vec<Participant> = participants_slice
        .iter()
        .map(|p| Participant::from(p))
        .collect();
    
    let rust_me = Participant::from(&me);

    match keygen::<ConcreteCurve>(&rust_participants, rust_me, threshold) {
        Ok(protocol) => {
            match run_protocol(protocol) {
                Ok(rust_output) => {
                    let c_output = CKeygenOutput {
                        private_share: rust_output.private_share.to_bytes().into(),
                        public_key: rust_output.public_key.to_uncompressed_bytes().into(),
                    };
                    
                    unsafe {
                        *output = c_output;
                    }
                    
                    CInitializationError::BadParameters // Success case
                },
                Err(_) => CInitializationError::BadParameters,
            }
        },
        Err(_) => CInitializationError::BadParameters,
    }
}

impl From<&CParticipant> for Participant {
    fn from(cp: &CParticipant) -> Self {
        Participant { id: cp.id }
    }
}

fn run_protocol<C: CSCurve>(protocol: impl Protocol<Output = KeygenOutput<C>>) -> Result<KeygenOutput<C>, InitializationError> {
    // This is a placeholder. You'll need to implement the actual protocol execution.
    // For now, it just returns an error.
    Err(InitializationError::BadParameters("Protocol execution not implemented".to_string()))
}

// Keep the original keygen function
#[no_mangle]
pub extern "C" fn keygen<C: CSCurve>(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };
    // Spec 1.1
    if threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "threshold must be <= participant count".to_string(),
        ));
    }

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            "participant list must contain this participant".to_string(),
        ));
    }

    let ctx = Context::new();
    let fut = do_keygen(ctx.shared_channel(), participants, me, threshold);
    Ok(make_protocol(ctx, fut))
}