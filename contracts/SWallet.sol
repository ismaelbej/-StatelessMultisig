pragma solidity >=0.4.21 <0.6.0;

contract SWallet {
/*
MAX_OWNERS: constant(int128) = 10
#WALLET_MSG: constant(bytes) = b"Multisig"
WALLET_MSG_HASH: constant(bytes32) = keccak256(b"Multisig")
MAX_MESSAGE: constant(int128) = 10000

numSigs: public(int128)
required: public(int128)
owners: public(address[MAX_OWNERS])
nonce: public(uint256)
index: map(address, int128)
*/

    uint256 constant MAX_OWNERS = 10;
    bytes constant WALLET_MSG = "Multisig";
    bytes32 constant WALLET_MSG_HASH = keccak256(WALLET_MSG);
    uint256 constant MAX_MESSAGE = 10000;

    uint256 public numSigs;
    uint256 public required;
    address[MAX_OWNERS] public owners;
    uint256 nonce;
    mapping (address => uint256) index;

/*
@public
def __init__(numSigs_: int128, required_: int128, r_: uint256[MAX_OWNERS], s_: uint256[MAX_OWNERS], v_: uint256[MAX_OWNERS]):
    assert numSigs_ <= MAX_OWNERS, "Too many owners"
    assert required_ <= numSigs_, "Too many signatues required"
    self.numSigs = numSigs_
    self.required = required_
    self.nonce = 1
    count: int128 = 0
    for i in range(MAX_OWNERS):
        if i < numSigs_:
            owner: address = ecrecover(WALLET_MSG_HASH, r_[i], s_[i], v_[i])
            if self.index[owner] == 0:
                self.index[owner] = 1 + i
                self.owners[i] = owner
                count += 1
            else:
                break
        else:
            break
    assert numSigs_ == count, "Invalid signature"
*/

    constructor(uint256 numSigs_, uint256 required_, bytes32[MAX_OWNERS] memory r_, bytes32[MAX_OWNERS] memory s_, uint8[MAX_OWNERS] memory v_) public {
        require(numSigs_ <= MAX_OWNERS, "Too many owners");
        require(required_ <= numSigs_, "Too many signatures required");
        numSigs = numSigs_;
        required = required_;
        nonce = 1;
        uint256 count = 0;
        for (uint256 i = 0; i < MAX_OWNERS; i += 1) {
            if (i < numSigs_) {
                address owner = ecrecover(WALLET_MSG_HASH, v_[i], r_[i], s_[i]);
                if (index[owner] == 0) {
                    index[owner] = 1 + i;
                    owners[count] = owner;
                    count += 1;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        require(numSigs_ == count, "Invalid signature");
    }

/*
@private
@constant
def verify_signatures(h: bytes32, required_: int128, numSigs_: int128, r_: uint256[MAX_OWNERS], s_: uint256[MAX_OWNERS], v_: uint256[MAX_OWNERS]) -> bool:
    assert numSigs_ >= required_, "Too few signatures"
    count: int128 = 0
    mask: uint256 = 0
    for i in range(MAX_OWNERS):
        if i < numSigs_ and count < required_:
            owner: address = ecrecover(h, r_[i], s_[i], v_[i])
            if self.index[owner] > 0:
                bit: uint256 = shift(2, self.index[owner] - 1)
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
*/

    function verify_signatures(bytes32 h, uint256 required_, uint256 numSigs_, bytes32[MAX_OWNERS] memory r_, bytes32[MAX_OWNERS] memory s_, uint8[MAX_OWNERS] memory v_) private view returns (bool) {
        require(numSigs_ >= required_, "Too few signatures");
        uint256 count = 0;
        uint256 mask = 0;
        for (uint256 i = 0; i < MAX_OWNERS; i += 1) {
            if (i < numSigs_ && count < required_) {
                address owner = ecrecover(h, v_[i], r_[i], s_[i]);
                require(index[owner] > 0, "Invalid signature");
                uint256 bit = 1 << (index[owner] - 1);
                require((mask & bit) == 0, "Duplicated signature");
                mask |= bit;
                count += 1;
            }
        }
        require(count >= required_, "Too few signatures");
        return true;
    }

/*
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
*/

    function make_hash(uint256 nonce_, address to_, bytes memory message_, uint256 gas_, uint256 value_) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                address(this),
                nonce_,
                to_,
                gas_,
                value_,
                message_
            )
        );
    }

/*
@public
def execute(to_: address, message_: bytes[MAX_MESSAGE], gas_: uint256, value_: uint256, numSigs_: int128, r_: uint256[MAX_OWNERS], s_: uint256[MAX_OWNERS], v_: uint256[MAX_OWNERS]):
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
*/
    function execute(address to_, bytes memory message_, uint256 gas_, uint256 value_, uint256 numSigs_, bytes32[MAX_OWNERS] memory r_, bytes32[MAX_OWNERS] memory s_, uint8[MAX_OWNERS] memory v_) public {
        bytes32 h = make_hash(
            nonce,
            to_,
            message_,
            gas_,
            value_
        );
        require(verify_signatures(h, required, numSigs_, r_, s_, v_), "Invalid message");
        nonce += 1;
        (bool result, )= to_.call.gas(gas_).value(value_)(message_);
    }
}
