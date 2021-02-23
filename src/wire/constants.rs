#![allow(warnings)]

pub mod field {
    #![allow(non_snake_case)]

    use core::ops::{Range, RangeFrom};

    pub type Field = Range<usize>;
    pub type Rest = RangeFrom<usize>;

    /*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Next Header   | Header Length |0| Packet Type |Version| RES.|1|
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Checksum             |           Controls            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                Sender's Host Identity Tag (HIT)               |
       |                                                               |
       |                                                               |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |               Receiver's Host Identity Tag (HIT)              |
       |                                                               |
       |                                                               |
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                                                               |
       /                        HIP Parameters                         /
       /                                                               /
       |                                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    */
    pub const NXT_HDR: usize = 0;
    pub const HDR_LEN: usize = 1;
    pub const PKT_TYPE: usize = 2;
    pub const VERSION: usize = 3;
    pub const CHECKSUM: Field = 4..6;
    pub const CONTROLS: Field = 6..8;
    pub const HIP_SENDERS_HIT: Field = 8..24;
    pub const HIP_RECIEVERS_HIT: Field = 24..40;

    pub fn HIP_PARAMS(length: usize) -> Field {
        HIP_RECIEVERS_HIT.end..(length)
    }

    pub const HIP_FIXED_HEADER_LENGTH_EXCL_8_BYTES: usize = 32;

    pub const HIP_I1_PACKET: usize = 0x1;
    pub const HIP_R1_PACKET: usize = 0x2;
    pub const HIP_I2_PACKET: usize = 0x3;
    pub const HIP_R2_PACKET: usize = 0x4;
    pub const HIP_UPDATE_PACKET: usize = 0x10;
    pub const HIP_NOTIFY_PACKET: usize = 0x11;
    pub const HIP_CLOSE_PACKET: usize = 0x12;
    pub const HIP_CLOSE_ACK_PACKET: usize = 0x13;

    //  HIP Parameter format i.e. [TLV Format SEC-5.2.1]: https://tools.ietf.org/html/rfc7401#section-5.2.1

    // 0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type            |C|             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                                                               |
    //  /                          Contents                             /
    //  /                                               +-+-+-+-+-+-+-+-+
    //  |                                               |    Padding    |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type         Type code for the parameter.  16 bits long, C-bit
    //               being part of the Type code.
    //  C            Critical.  One if this parameter is critical and
    //               MUST be recognized by the recipient, zero otherwise.
    //               The C-bit is considered to be a part of the Type
    //               field.  Consequently, critical parameters are always
    //               odd, and non-critical ones have an even value.
    //  Length       Length of the Contents, in bytes, excluding Type,
    //               Length, and Padding
    //  Contents     Parameter specific, defined by Type
    //  Padding      Padding, 0-7 bytes, added if needed

    pub const HIP_TLV_TYPE_OFFSET: Field = 0..2;
    pub const HIP_TLV_CRITICAL_BIT_OFFSET: Field = 0..2;
    pub const HIP_TLV_LENGTH_OFFSET: Field = 2..4;

    pub const HIP_TLV_LENGTH_LENGTH: usize = 0x2;
    pub const HIP_TLV_TYPE_LENGTH: usize = 0x2;
    pub const HIP_TLV_CRITICAL_BIT_LENGTH: usize = 0x1;

    pub const HIP_PROTOCOL: usize = 0x8B;
    pub const HIP_IPPROTO_NONE: usize = 0x3B;
    pub const HIP_VERSION: usize = 0x2;
    pub const HIP_HEADER_LENGTH: usize = 0x28;
    pub const HIP_TLV_LENGTH: usize = 0x4;
    pub const HIP_DEFAULT_PACKET_LENGTH: usize = 0x4;
    pub const HIP_FRAGMENT_LENGTH: usize = 0x578;

    // [R1_COUNTER SEC-5.2.3]: https://tools.ietf.org/html/rfc7401#section-5.2.3

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                       Reserved, 4 bytes                       |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                R1 generation counter, 8 bytes                 |
    //  |                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type           129
    //  Length         12
    //  R1 generation
    //    counter      The current generation of valid puzzles

    pub const HIP_R1_COUNTER_OFFSET: Field = 8..16;

    pub const HIP_R1_COUNTER_TYPE: usize = 0x81;
    pub const HIP_R1_COUNTER_LENGTH: usize = 0x0C;
    pub const HIP_R1_COUNTER_RES_LEN: usize = 0x4;
    pub const HIP_R1_GEN_COUNTER_LEN: usize = 0x8;

    //     [5.2.4.  PUZZLE]: https://tools.ietf.org/html/rfc7401#section-5.2.4

    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |             Type              |             Length            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |  #K, 1 byte   |    Lifetime   |        Opaque, 2 bytes        |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                      Random #I, RHASH_len / 8 bytes           |
    //    /                                                               /
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //    Type           257
    //    Length         4 + RHASH_len / 8
    //    #K             #K is the number of verified bits
    //    Lifetime       puzzle lifetime 2^(value - 32) seconds
    //    Opaque         data set by the Responder, indexing the puzzle
    //    Random #I      random number of size RHASH_len bits

    pub const HIP_PUZZLE_TYPE: usize = 257;
    pub const RHASH_LEN: usize = 0x20;
    pub const HIP_PUZZLE_LENGTH: usize = 4 + RHASH_LEN;

    pub const HIP_PUZZLE_K_OFFSET: Field = 4..5;
    pub const HIP_PUZZLE_LIFETIME_OFFSET: Field = 5..6;
    pub const HIP_PUZZLE_OPAQUE_OFFSET: Field = 6..8;
    pub const HIP_PUZZLE_RANDOM_I_OFFSET: Rest = 8..;

    pub const HIP_PUZZLE_K_LENGTH: usize = 0x1;
    pub const HIP_PUZZLE_LIFETIME_LENGTH: usize = 0x1;
    pub const HIP_PUZZLE_OPAQUE_LENGTH: usize = 0x2;
    pub const HIP_PUZZLE_RANDOM_I_LENGTH: usize = RHASH_LEN;

    // [5.2.5.  SOLUTION]: https://tools.ietf.org/html/rfc7401#section-5.2.5

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |  #K, 1 byte   |   Reserved    |        Opaque, 2 bytes        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                      Random #I, n bytes                       |
    //  /                                                               /
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |            Puzzle solution #J, RHASH_len / 8 bytes            |
    //  /                                                               /
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type                321
    //  Length              4 + RHASH_len / 4
    //  #K                  #K is the number of verified bits
    //  Reserved            zero when sent, ignored when received
    //  Opaque              copied unmodified from the received PUZZLE
    //                      parameter
    //  Random #I           random number of size RHASH_len bits
    //  Puzzle solution #J  random number of size RHASH_len bits

    pub const HIP_SOLUTION_TYPE: usize = 321;

    pub const HIP_SOLUTION_RANDOM_I_OFFSET: Field = 8..40;
    pub const HIP_SOLUTION_RANDOM_I_LENGTH: usize = RHASH_LEN;

    pub const HIP_SOLUTION_K_LENGTH: usize = 0x1;
    pub const HIP_SOLUTION_K_OFFSET: Field = 4..5;

    pub const HIP_SOLUTION_J_OFFSET: Field = 40..72;
    pub const HIP_SOLUTION_J_LENGTH: usize = RHASH_LEN;

    pub const HIP_SOLUTION_LENGTH: usize = 0x4 + RHASH_LEN * 2;
    pub const HIP_SOLUTION_RESERVED_LENGTH: usize = 0x1;
    pub const HIP_SOLUTION_RESERVED_OFFSET: Field = 5..6;

    pub const HIP_SOLUTION_OPAQUE_LENGTH: usize = 0x2;
    pub const HIP_SOLUTION_OPAQUE_OFFSET: Field = 6..8;

    // [5.2.6.  DH_GROUP_LIST]: https://tools.ietf.org/html/rfc7401#section-5.2.6

    //       0                   1                   2                   3
    //       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //      |             Type              |             Length            |
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //      | DH GROUP ID #1| DH GROUP ID #2| DH GROUP ID #3| DH GROUP ID #4|
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //      | DH GROUP ID #n|                Padding                        |
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //      Type           511
    //      Length         number of DH Group IDs
    //      DH GROUP ID    identifies a DH GROUP ID supported by the host.
    //                     The list of IDs is ordered by preference of the
    //                     host.  The possible DH Group IDs are defined
    //                     in the DIFFIE_HELLMAN parameter.  Each DH
    //                     Group ID is one octet long.

    pub const HIP_DH_GROUP_LIST_TYPE: usize = 0x1FF;
    pub const HIP_DH_GROUP_LIST_OFFSET: Rest = 4..;

    // [5.2.7.  DIFFIE_HELLMAN]: https://tools.ietf.org/html/rfc7401#section-5.2.7

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |   Group ID    |      Public Value Length      | Public Value  /
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  /                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  /                               |            Padding            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type           513
    //  Length         length in octets, excluding Type, Length, and
    //                 Padding
    //  Group ID       identifies values for p and g as well as the KDF
    //  Public Value   length of the following Public Value in octets
    //    Length
    //  Public Value   the sender's public Diffie-Hellman key

    pub const HIP_DH_TYPE: usize = 0x201;
    pub const HIP_DH_GROUP_ID_OFFSET: Field = 4..5;
    pub const HIP_PUBLIC_VALUE_LENGTH_OFFSET: Field = 5..7;
    pub const HIP_PUBLIC_VALUE_OFFSET: Rest = 7..;

    pub const HIP_GROUP_ID_LENGTH: usize = 0x1;
    pub const HIP_PUBLIC_VALUE_LENGTH_LENGTH: usize = 0x2;

    //     [RFC 7401 5.2.8. HIP_CIPHER]: https://tools.ietf.org/html/rfc7401#section-5.2.8

    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |             Type              |             Length            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          Cipher ID #1         |          Cipher ID #2         |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          Cipher ID #n         |             Padding           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //    Type           579
    //    Length         length in octets, excluding Type, Length, and
    //                   Padding
    //    Cipher ID      identifies the cipher algorithm to be used for
    //                   encrypting the contents of the ENCRYPTED parameter

    pub const HIP_CIPHER_TYPE: usize = 0x243;
    pub const HIP_CIPHER_LIST_OFFSET: Rest = 4..;

    // [RFC 7401 5.2.9.  HOST_ID]: https://tools.ietf.org/html/rfc7401#section-5.2.9

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |          HI Length            |DI-Type|      DI Length        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |          Algorithm            |         Host Identity         /
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  /                               |       Domain Identifier       /
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  /                                               |    Padding    |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type               705
    //  Length             length in octets, excluding Type, Length, and
    //                     Padding
    //  HI Length          length of the Host Identity in octets
    //  DI-Type            type of the following Domain Identifier field
    //  DI Length          length of the Domain Identifier field in octets
    //  Algorithm          index to the employed algorithm
    //  Host Identity      actual Host Identity
    //  Domain Identifier  the identifier of the sender

    pub const HIP_HI_TYPE: usize = 0x2C1;

    pub const HIP_HI_LENGTH_LENGTH: usize = 0x2;
    pub const HIP_DI_LENGTH_LENGTH: usize = 0x2;
    pub const HIP_ALGORITHM_LENGTH: usize = 0x2;

    pub const HIP_HI_LENGTH_OFFSET: Field = 4..6;
    pub const HIP_DI_LENGTH_OFFSET: Field = 6..8;
    pub const HIP_ALGORITHM_OFFSET: Field = 8..10;
    pub const HIP_HI_OFFSET: Rest = 10..;

    // [RFC 7401 5.2.10.  HIT_SUITE_LIST ]: https://tools.ietf.org/html/rfc7401#section-5.2.10
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |             Type              |             Length            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |     ID #1     |     ID #2     |     ID #3     |     ID #4     |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |     ID #n     |                Padding                        |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //    Type           715
    //    Length         number of HIT Suite IDs
    //    ID             identifies a HIT Suite ID supported by the host.
    //                   The list of IDs is ordered by preference of the
    //                   host.  Each HIT Suite ID is one octet long.  The
    //                   four higher-order bits of the ID field correspond
    //                   to the HIT Suite ID in the ORCHID OGA ID field.  The
    //                   four lower-order bits are reserved and set to 0
    //                   by the sender.  The reception of an ID with the
    //                   four lower-order bits not set to 0 SHOULD be
    //                   considered as an error that MAY result in a
    //                   NOTIFICATION of type UNSUPPORTED_HIT_SUITE.

    pub const HIP_HIT_SUITS_TYPE: usize = 0x2CB;
    pub const HIP_HIT_SUITS_OFFSET: Rest = 4..;

    //  [RFC 7401 5.2.11. TRANSPORT_FORMAT_LIST]: https://tools.ietf.org/html/rfc7401#section-5.2.11
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |             Type              |             Length            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          TF type #1           |           TF type #2          /
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    /          TF type #n           |             Padding           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //    Type           2049
    //    Length         2x number of TF types
    //    TF Type        identifies a transport format (TF) type supported
    //                   by the host.  The TF type numbers correspond to
    //                   the HIP parameter type numbers of the respective
    //                   transport format parameters.  The list of TF types
    //                   is ordered by preference of the sender.

    pub const HIP_TRANSPORT_FORMAT_LIST_TYPE: usize = 0x801;
    pub const HIP_TRANSPORT_FORMAT_LIST_OFFSET: Rest = 4..;

    // [RFC 7401 5.2.12. HIP_MAC]: https://tools.ietf.org/html/rfc7401#section-5.2.12]
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |             Type              |             Length            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                                                               |
    //    |                             HMAC                              |
    //    /                                                               /
    //    /                               +-------------------------------+
    //    |                               |            Padding            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //    Type           61505
    //    Length         length in octets, excluding Type, Length, and
    //                   Padding
    //    HMAC           HMAC computed over the HIP packet, excluding the
    //                   HIP_MAC parameter and any following parameters,
    //                   such as HIP_SIGNATURE, HIP_SIGNATURE_2,
    //                   ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED.
    //                   The Checksum field MUST be set to zero, and the
    //                   HIP header length in the HIP common header MUST be
    //                   calculated not to cover any excluded parameters
    //                   when the HMAC is calculated.  The size of the
    //                   HMAC is the natural size of the hash computation
    //                   output depending on the used hash function.

    pub const HIP_MAC_TYPE: usize = 0xF041;
    pub const HIP_MAC_OFFSET: Rest = 4..;

    // [RFC 7401 5.2.13. HIP_MAC_2]: https://tools.ietf.org/html/rfc7401#section-5.2.13]

    pub const HIP_MAC_2_TYPE: usize = 0xF081;
    pub const HIP_MAC_2_OFFSET: Rest = 4..;

    // [RFC 7401 5.2.14.  HIP_SIGNATURE]: https://tools.ietf.org/html/rfc7401#section-5.2.14]

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |    SIG alg                    |            Signature          /
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  /                               |             Padding           |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type           61697
    //  Length         length in octets, excluding Type, Length, and
    //                 Padding
    //  SIG alg        signature algorithm
    //  Signature      the signature is calculated over the HIP packet,
    //                 excluding the HIP_SIGNATURE parameter and any
    //                 parameters that follow the HIP_SIGNATURE
    //                 parameter.  When the signature is calculated, the
    //                 Checksum field MUST be set to zero, and the HIP
    //                 header length in the HIP common header MUST be
    //                 calculated only up to the beginning of the
    //                 HIP_SIGNATURE parameter.

    pub const HIP_SIG_TYPE: usize = 0xF101;
    pub const HIP_SIG_ALG_TYPE_OFFSET: Field = 4..6;
    pub const HIP_SIG_OFFSET: Rest = 6..;

    pub const HIP_SIG_ALG_TYPE_LENGTH: usize = 0x2;

    // [RFC 7401 5.2.15.  HIP_SIGNATURE_2]: https://tools.ietf.org/html/rfc7401#section-5.2.15]

    pub const HIP_SIG_2_TYPE: usize = 0xF0C1;
    pub const HIP_SIG_ALG_TYPE_OFFSET_2: Field = 4..6;
    pub const HIP_SIG_OFFSET_2: Rest = 6..;

    pub const HIP_SIG_ALG_TYPE_LENGTH_2: usize = 0x2;

    // [RFC 7401 5.2.16. SEQ]: https://tools.ietf.org/html/rfc7401#section-5.2.16]

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                            Update ID                          |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type            385
    //  Length          4
    //  Update ID       32-bit sequence number

    pub const HIP_SEQ_TYPE: usize = 0x181;
    pub const HIP_UPDATE_ID_OFFSET: Field = 4..8;

    pub const HIP_UPDATE_ID_LENGTH: usize = 0x4;

    // [RFC 7401 5.2.17.  ACK]: https://tools.ietf.org/html/rfc7401#section-5.2.17]

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                       peer Update ID 1                        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  /                       peer Update ID n                        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type             449
    //  Length           length in octets, excluding Type and Length
    //  peer Update ID   32-bit sequence number corresponding to the
    //                   Update ID being ACKed

    pub const HIP_ACK_TYPE: usize = 0x1C1;
    pub const HIP_ACK_ID_OFFSET: Rest = 4..;

    // [RFC 7401 5.2.18.  ENCRYPTED]: https://tools.ietf.org/html/rfc7401#section-5.2.18]

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           Reserved                            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                              IV                               /
    //  /                                                               /
    //  /                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
    //  /                        Encrypted data                         /
    //  /                                                               /
    //  /                               +-------------------------------+
    //  /                               |            Padding            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type           641
    //  Length         length in octets, excluding Type, Length, and
    //                 Padding
    //  Reserved       zero when sent, ignored when received
    //  IV             Initialization vector, if needed, otherwise
    //                 nonexistent.  The length of the IV is inferred from
    //                 the HIP_CIPHER.
    //  Encrypted      The data is encrypted using the encryption algorithm
    //    data         defined in the HIP_CIPHER parameter.

    pub const HIP_ENCRYPTED_TYPE: usize = 0x281;
    pub const HIP_ENCRYPTED_RESERVED_LENGTH: usize = 0x4;

    pub const HIP_ENCRYPTED_IV_OFFSET: Rest = 8..;

    pub const HIP_NOTIFICATION_TYPE: usize = 0x340;
    pub const HIP_NOTIFICATION_RESERVED_LENGTH: usize = 0x2;
    pub const HIP_NOTIFY_DATA_TYPE_LENGTH: usize = 0x2;

    pub const HIP_NOTIFICATION_RESERVED_OFFSET: Field = 4..6;
    pub const HIP_NOTIFY_MESSAGE_TYPE_OFFSET: Field = 6..8;
    pub const HIP_NOTIFICATION_DATA_OFFSET: Rest = 8..;

    //     [RFC 7401 5.2.19.  NOTIFICATION]: https://tools.ietf.org/html/rfc7401#section-5.2.19]

    //    The NOTIFICATION parameter is used to transmit informational data,
    //    such as error conditions and state transitions, to a HIP peer.  A
    //    NOTIFICATION parameter may appear in NOTIFY packets.  The use of the
    //    NOTIFICATION parameter in other packet types is for further study.

    //       0                   1                   2                   3
    //       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //      |             Type              |             Length            |
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //      |          Reserved             |      Notify Message Type      |
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //      |                                                               /
    //      /                   Notification Data                           /
    //      /                                               +---------------+
    //      /                                               |     Padding   |
    //      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //      Type             832
    //      Length           length in octets, excluding Type, Length, and
    //                       Padding
    //      Reserved         zero when sent, ignored when received
    //      Notify Message   specifies the type of notification
    //        Type
    //      Notification     informational or error data transmitted in
    //        Data           addition to the Notify Message Type.  Values
    //                       for this field are type specific (see below).

    //  Error messages
    pub const UNSUPPORTED_CRITICAL_PARAMETER_TYPE: usize = 0x1;
    pub const INVALID_SYNTAX: usize = 0x7;
    pub const NO_DH_PROPOSAL_CHOSEN: usize = 0xE;
    pub const INVALID_DH_CHOSEN: usize = 0xF;
    pub const NO_HIP_PROPOSAL_CHOSEN: usize = 0x10;
    pub const INVALID_HIP_CIPHER_CHOSEN: usize = 0x11;
    pub const UNSUPPORTED_HIT_SUITE: usize = 0x14;
    pub const AUTHENTICATION_FAILED: usize = 0x18;
    pub const CHECKSUM_FAILED: usize = 0x1A;
    pub const HIP_MAC_FAILED: usize = 0x1C;
    pub const ENCRYPTION_FAILED: usize = 0x20;
    pub const INVALID_HIT: usize = 0x28;
    pub const BLOCKED_BY_POLICY: usize = 0x2a;
    pub const RESPONDER_BUSY_PLEASE_RETRY: usize = 0x2c;
    pub const I2_ACKNOWLEDGEMENT: usize = 0x4000;

    // [RFC 7401 5.2.20.  ECHO_REQUEST_SIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.20]

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                 Opaque data (variable length)                 |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type          897
    //  Length        length of the opaque data in octets
    //  Opaque data   opaque data, supposed to be meaningful only to
    //                the node that sends ECHO_REQUEST_SIGNED and
    //                receives a corresponding ECHO_RESPONSE_SIGNED or
    //                ECHO_RESPONSE_UNSIGNED

    pub const HIP_ECHO_REQUEST_SIGNED_TYPE: usize = 0x381;
    pub const HIP_ECHO_REQUEST_SIGNED_OFFSET: Rest = 4..;

    // [RFC 7401 5.2.21.  ECHO_REQUEST_UNSIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.21]

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                 Opaque data (variable length)                 |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type          63661
    //  Length        length of the opaque data in octets
    //  Opaque data   opaque data, supposed to be meaningful only to
    //                the node that sends ECHO_REQUEST_UNSIGNED and
    //                receives a corresponding ECHO_RESPONSE_UNSIGNED

    pub const HIP_ECHO_REQUEST_UNSIGNED_TYPE: usize = 0xF8AD;
    pub const HIP_ECHO_REQUEST_UNSIGNED_OFFSET: Rest = 4..;

    // [RFC 7401 5.2.22.  ECHO_RESPONSE_SIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.22]

    // 5.2.22.  ECHO_RESPONSE_SIGNED

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                 Opaque data (variable length)                 |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type          961
    //  Length        length of the opaque data in octets
    //  Opaque data   opaque data, copied unmodified from the
    //                ECHO_REQUEST_SIGNED or ECHO_REQUEST_UNSIGNED
    //                parameter that triggered this response

    pub const HIP_ECHO_RESPONSE_SIGNED_TYPE: usize = 0x3C1;
    pub const HIP_ECHO_RESPONSE_SIGNED_OFFSET: Rest = 4..;

    // [RFC 7401 5.2.23.  ECHO_RESPONSE_UNSIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.23

    //   0                   1                   2                   3
    //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |             Type              |             Length            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                 Opaque data (variable length)                 |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  Type          63425
    //  Length        length of the opaque data in octets
    //  Opaque data   opaque data, copied unmodified from the
    //                ECHO_REQUEST_SIGNED or ECHO_REQUEST_UNSIGNED
    //                parameter that triggered this response

    pub const HIP_ECHO_RESPONSE_UNSIGNED_TYPE: usize = 0xF7C1;
    pub const HIP_ECHO_RESPONSE_UNSIGNED_OFFSET: Rest = 4..;

    //     [RFC 7402 5.1.2.  ESP_TRANSFORM]: https://tools.ietf.org/html/rfc7402#section-5.1.2
    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |             Type              |             Length            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          Reserved             |           Suite ID #1         |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          Suite ID #2          |           Suite ID #3         |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |          Suite ID #n          |             Padding           |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //    Type           4095
    //    Length         length in octets, excluding Type, Length, and
    //                   padding.
    //    Reserved       zero when sent, ignored when received.
    //    Suite ID       defines the ESP Suite to be used.

    pub const HIP_ESP_TRANSFORM_TYPE: usize = 0xFFF;
    pub const HIP_SUITS_LIST_OFFSET: Rest = 4..;
    pub const HIP_SUITS_RESERVED_LENGTH: usize = 0x2;

    //     [RFC 7402 5.1.1.  ESP_INFO]: https://tools.ietf.org/html/rfc7402#section-5.1.1

    //     0                   1                   2                   3
    //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |             Type              |             Length            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |           Reserved            |         KEYMAT Index          |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                            OLD SPI                            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //    |                            NEW SPI                            |
    //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //    Type           65
    //    Length         12
    //    KEYMAT Index   index, in bytes, where to continue to draw ESP keys
    //                   from KEYMAT.  If the packet includes a new
    //                   Diffie-Hellman key and the ESP_INFO is sent in an
    //                   UPDATE packet, the field MUST be zero.  If the
    //                   ESP_INFO is included in base exchange messages, the
    //                   KEYMAT Index must have the index value of the point
    //                   from where the ESP SA keys are drawn.  Note that
    //                   the length of this field limits the amount of
    //                   keying material that can be drawn from KEYMAT.  If
    //                   that amount is exceeded, the packet MUST contain
    //                   a new Diffie-Hellman key.
    //    OLD SPI        old SPI for data sent to address(es) associated
    //                   with this SA.  If this is an initial SA setup, the
    //                   OLD SPI value is zero.
    //    NEW SPI        new SPI for data sent to address(es) associated
    //                   with this SA.

    pub const HIP_ESP_INFO_TYPE: usize = 0x41;
    pub const HIP_ESP_INFO_RESERVED_LENGTH: usize = 0x2;
    pub const HIP_ESP_INFO_KEYMAT_INDEX_LENGTH: usize = 0x2;
    pub const HIP_ESP_INFO_KEYMAT_INDEX_OFFSET: Field = 6..8;
    pub const HIP_ESP_INFO_OLD_SPI_LENGTH: usize = 0x4;
    pub const HIP_ESP_INFO_OLD_SPI_OFFSET: Field = 8..12;
    pub const HIP_ESP_INFO_NEW_SPI_LENGTH: usize = 0x4;
    pub const HIP_ESP_INFO_NEW_SPI_OFFSET: Field = 12..16;

    //     [RFC 4303 2.  ESP Packet Format]: https://tools.ietf.org/html/rfc4303#section-2

    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
    // |               Security Parameters Index (SPI)                 | ^Integrity
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
    // |                      Sequence Number                          | |ered
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
    // |                    Payload Data* (variable)                   | |   ^
    // ~                                                               ~ |   |
    // |                                                               | |Confidentiality
    // +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
    // |               |     Padding (0-255 bytes)                     | |ered*
    // +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
    // |                               |  Pad Length   | Next Header   | v   v
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
    // |         Integrity Check Value-ICV   (variable)                |
    // ~                                                               ~
    // |                                                               |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //            Top-Level Format of an ESP Packet

    pub const ESP_TRANSPORT_FORMAT: usize = 0x0FFF;

    pub const ESP_PROTOCOL: usize = 0x32;
    pub const ESP_SPI_LENGTH: usize = 0x4;
    pub const ESP_SEQUENCE_LENGTH: usize = 0x4;

    pub const ESP_SPI_OFFSET: Field = 0..4;
    pub const ESP_SEQUENCE_OFFSET: Field = 4..8;
    pub const ESP_PAYLOAD_OFFSET: Rest = 8..;

    pub const ESP_IV_LENGTH: usize = 0x10;

    // IPv6 constants
    pub const IPV6_PROTOCOL: usize = 0x29;
    pub const IPV6_VERSION: usize = 0x6;

    // IPv4 constants
    pub const IPV4_DEFAULT_TTL: usize = 0x80;
    pub const IPV4_IHL_NO_OPTIONS: usize = 0x5;
    pub const IPV4_VERSION: usize = 0x4;

}
