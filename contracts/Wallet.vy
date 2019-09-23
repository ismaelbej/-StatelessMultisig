MAX_OWNERS: constant(uint256) = 10
#WALLET_MSG: constant(bytes) = b"Multisig"
WALLET_MSG_HASH: constant(bytes32) = keccak256(b"Multisig")
MAX_MESSAGE: constant(uint256) = 10000

numSigs: public(uint256)
required: public(uint256)
owners: public(address[MAX_OWNERS])
nonce: public(uint256)
index: map(address, uint256)

@public
def __init__(numSigs_: uint256, required_: uint256, r_: uint256[MAX_OWNERS], s_: uint256[MAX_OWNERS], v_: uint256[MAX_OWNERS]):
    assert numSigs_ <= MAX_OWNERS, "Too many owners"
    assert required_ <= numSigs_, "Too many signatues required"
    self.numSigs = numSigs_
    self.required = required_
    self.nonce = 1
    count: int128 = 0
    for i in range(MAX_OWNERS):
        if convert(i, uint256) < numSigs_:
            owner: address = ecrecover(WALLET_MSG_HASH, v_[i], r_[i], s_[i])
            if self.index[owner] == 0:
                self.index[owner] = 1 + convert(i, uint256)
                self.owners[count] = owner
                count += 1
            else:
                break
        else:
            break
    assert numSigs_ == convert(count, uint256), "Invalid signature"

@private
@constant
def verify_signatures(h: bytes32, required_: uint256, numSigs_: uint256, r_: uint256[MAX_OWNERS], s_: uint256[MAX_OWNERS], v_: uint256[MAX_OWNERS]) -> bool:
    assert numSigs_ >= required_, "Too few signatures"
    count: uint256 = 0
    mask: uint256 = 0
    for i in range(MAX_OWNERS):
        if convert(i, uint256) < numSigs_ and count < required_:
            owner: address = ecrecover(h, r_[i], s_[i], v_[i])
            if self.index[owner] > 0:
                bit: uint256 = shift(2, convert(self.index[owner], int128) - 1)
                if bitwise_and(mask, bit) == 0:
                    mask = bitwise_or(mask, bit)
                    count += 1
                else:
                    break
            else:
                break
        else:
            break
    return count >= required_

@public
@constant
def make_hash(nonce_: uint256, to_: address, message_: bytes[MAX_MESSAGE], gas_: uint256, value_: uint256) -> bytes32:
    return keccak256(
        concat(b"",
            convert(self, bytes32),
            convert(nonce_, bytes32),
            convert(to_, bytes32),
            convert(gas_, bytes32),
            convert(value_, bytes32),
            message_,
        )
    )

@public
def execute(to_: address, message_: bytes[MAX_MESSAGE], gas_: uint256, value_: uint256, numSigs_: uint256, r_: uint256[MAX_OWNERS], s_: uint256[MAX_OWNERS], v_: uint256[MAX_OWNERS]):
    h: bytes32 = self.make_hash(
        self.nonce,
        to_,
        message_,
        gas_,
        value_,
    )
    assert self.verify_signatures(h, self.required, numSigs_, r_, s_, v_), "Invalid message"
    self.nonce += 1
    raw_call(to_, message_, outsize=0, gas=gas_, value=value_, delegate_call=False)
