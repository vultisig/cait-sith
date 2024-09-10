/*#[no_mangle]
pub extern "C" fn rust_function_add(arg1: i32, arg2: i32) -> i32 {
    arg1 + arg2
}

use crate::{
    //CSCurve,
    KeygenOutput,
    protocol::Protocol,
    participants::ParticipantList,
    protocol::{InitializationError, Participant, internal::{Context, make_protocol}},
};
use crate::keyshare::do_keygen;
use k256::{Secp256k1, Scalar, AffinePoint};

use crate::compat::CSCurve;
//use k256::Secp256k1;

type ConcreteCurve = Secp256k1;


// This is our C-compatible struct
#[repr(C)]
pub struct KeygenOutputC {
    private_share: *mut Scalar,
    public_key: *mut AffinePoint,
}

use std::os::raw::c_char;
use std::ffi::CString;

#[repr(C)]
pub enum CResult {
    Ok(*mut KeygenOutputC),
    Err(*const c_char),
}

#[no_mangle]
pub extern "C" fn test(
    participants: *const u32,
    participant_count: usize,
    me: u32,
    threshold: u32,
) -> CResult {
    let participants: Vec<Participant> = unsafe {
        std::slice::from_raw_parts(participants, participant_count)
            .iter()
            .map(|&p| Participant::from(p))
            .collect()
    };

    // Convert 'me' to Participant type
    let me_participant = Participant::from(me);

    // Call the original keygen function
    match keygen::<ConcreteCurve>(&participants, me_participant, threshold as usize) {
        Ok(protocol) => {
            // Execute the protocol to get the KeygenOutput
            let output = protocol.run().expect("Protocol execution failed");
            let c_output = Box::new(KeygenOutputC {
                private_share: Box::into_raw(Box::new(output.private_share)),
                public_key: Box::into_raw(Box::new(output.public_key)),
            });
            CResult::Ok(Box::into_raw(c_output))
        }
        Err(e) => {
            let error_message = CString::new(e.to_string()).unwrap();
            CResult::Err(error_message.into_raw())
        }
    }
}

//function to free the allocated memory
#[no_mangle]
pub extern "C" fn free_keygen_output(ptr: *mut KeygenOutputC) {
    if !ptr.is_null() {
        unsafe {
            Box::from_raw(ptr);
        }
    }
}

pub fn keygen<C: CSCurve>(
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

// Implement conversion from KeygenOutput<ConcreteCurve> to KeygenOutputC
/*impl From<KeygenOutput<ConcreteCurve>> for KeygenOutputC {
    fn from(output: KeygenOutput<ConcreteCurve>) -> Self {
        KeygenOutputC {
            private_share: Box::into_raw(Box::new(output.private_share)),
            public_key: Box::into_raw(Box::new(output.public_key)),
        }
    }
}

#[no_mangle]
pub extern "C" fn keygen<C : CSCurve>(
    participants: *const Participant,
    participants_len: usize,
    me: Participant,
    threshold: usize,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError> {
//) -> *mut KeygenOutputC {
    let participants_slice = unsafe { std::slice::from_raw_parts(participants, participants_len) };

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
}*/

*/