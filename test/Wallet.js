const { ecsign, ecrecover, keccak256, privateToAddress, publicToAddress, bufferToHex } = require("ethereumjs-util");
const Wallet = artifacts.require("Wallet");

const privateKey = "6326d5166aff2daf32d50bc73b81e2b515f941d3778e82c7a6306fb7e1b894fd";

function makeArray(obj, fill = undefined, len = 10) {
    let result = [obj];
    while (result.length < len) {
        result = result.concat([fill]);
    }
    return result;
}

contract("Wallet", (accounts) => {
    it("Create signature", async () => {
        const message = "Multisig";
        const pkey = Buffer.from(privateKey, "hex");
        const address = privateToAddress(pkey);
        const hash = keccak256(message);
        const signature = ecsign(hash, pkey);
        const pubKey = ecrecover(hash, signature.v, signature.r, signature.s);
        const address2 = publicToAddress(pubKey);
        assert.equal(bufferToHex(address), bufferToHex(address2), "Matches");
    });
    it("Create wallet", async () => {
        const message = "Multisig";
        const pkey = Buffer.from(privateKey, "hex");
        const address = bufferToHex(privateToAddress(pkey));
        const hash = keccak256(message);
        const signature = ecsign(hash, pkey);
        const wallet = await Wallet.new(1, 1, makeArray(signature.r, Buffer.alloc(32)), makeArray(signature.s, Buffer.alloc(32)), makeArray(signature.v, Buffer.alloc(1)));
        const required = await wallet.required();
        assert.equal(required.toNumber(), 1, "Required signatures");
        const owner = await wallet.owners(0);
        assert.equal(owner.toLowerCase(), address, "Only owner");
    });
});