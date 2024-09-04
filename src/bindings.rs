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
use k256::{Secp256k1, Scalar, AffinePoint};

type ConcreteCurve = Secp256k1;

// This is our C-compatible struct
#[repr(C)]
pub struct KeygenOutputC {
    private_share: *mut Scalar,
    public_key: *mut AffinePoint,
}

// Implement conversion from KeygenOutput<ConcreteCurve> to KeygenOutputC
impl From<KeygenOutput<ConcreteCurve>> for KeygenOutputC {
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
}