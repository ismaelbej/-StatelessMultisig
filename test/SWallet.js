const { ecsign, ecrecover, keccak256, privateToAddress, publicToAddress, bufferToHex } = require("ethereumjs-util");
const SWallet = artifacts.require("SWallet");

const privateKey = "6326d5166aff2daf32d50bc73b81e2b515f941d3778e82c7a6306fb7e1b894fd";

contract("SWallet", (accounts) => {
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
        const wallet = await SWallet.new(1, 1, [signature.r], [signature.s], [signature.v]);
        const required = await wallet.required();
        assert.equal(required.toNumber(), 1, "Required signatures");
        const owner = await wallet.owners(0);
        assert.equal(owner.toLowerCase(), address, "Only owner");
    });
});