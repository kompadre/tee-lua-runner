//! Framing tests: roundtrips, EOF semantics, bounds.

use tee_proto::framing::{read_frame, write_frame};

#[test]
fn read_roundtrip_eof_and_bounds() {
    let mut buf = Vec::new();
    write_frame(&mut buf, b"payload-1").unwrap();
    write_frame(&mut buf, &[7u8; 70]).unwrap();

    let mut cursor = &buf[..];
    assert_eq!(read_frame(&mut cursor).unwrap().unwrap(), b"payload-1");
    assert_eq!(read_frame(&mut cursor).unwrap().unwrap(), vec![7u8; 70]);
    // Clean EOF at a frame boundary.
    assert!(read_frame(&mut cursor).unwrap().is_none());

    // Zero length is invalid.
    let zero = [0u8, 0, 0, 0];
    let err = read_frame(&mut &zero[..]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    // Oversized declared length is refused without allocating.
    let huge = u32::MAX.to_be_bytes();
    let err = read_frame(&mut &huge[..]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    // Declared length beyond available bytes → UnexpectedEof.
    let truncated = [0u8, 0, 0, 8, 1, 2];
    let err = read_frame(&mut &truncated[..]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}
