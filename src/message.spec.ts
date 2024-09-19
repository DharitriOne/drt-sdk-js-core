import { UserVerifier } from "@dharitri-sdk/wallet";
import { assert } from "chai";
import { DEFAULT_MESSAGE_VERSION, SDK_JS_SIGNER, UNKNOWN_SIGNER } from "./constants";
import { Message, MessageComputer } from "./message";
import { TestWallet, loadTestWallets } from "./testutils";

describe("test message", () => {
    let alice: TestWallet;
    const messageComputer = new MessageComputer();

    before(async function () {
        ({ alice } = await loadTestWallets());
    });

    it("should test message compute bytes for signing", async () => {
        const data = Buffer.from("test message");

        const message = new Message({
            data: data,
        });

        const serialized = messageComputer.computeBytesForSigning(message);

        assert.equal(
            Buffer.from(serialized).toString("hex"),
            "0f6fce3fa6130fc58a25eaff6e157ea1bcb02fbf9773dca514dfaf3cd1e0bdfe",
        );
    });

    it("should create, sign, pack, unpack and verify message", async () => {
        const data = Buffer.from("test");

        const message = new Message({
            data: data,
            address: alice.getAddress(),
        });

        message.signature = await alice.signer.sign(messageComputer.computeBytesForSigning(message));

        assert.equal(
            Buffer.from(message.signature).toString("hex"),
            "70e7cbd157568ce5250ced7c3e6caf97669c47142cc337b135bbd7a438ae962fa84a426fd1b64fcdcdecc3a2935b7db9b8d35035eaae153126608c2c03602109",
        );

        const packedMessage = messageComputer.packMessage(message);
        assert.deepEqual(packedMessage, {
            address: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            message: "74657374",
            signature:
                "70e7cbd157568ce5250ced7c3e6caf97669c47142cc337b135bbd7a438ae962fa84a426fd1b64fcdcdecc3a2935b7db9b8d35035eaae153126608c2c03602109",
            version: 1,
            signer: SDK_JS_SIGNER,
        });

        const unpackedMessage = messageComputer.unpackMessage(packedMessage);
        assert.deepEqual(unpackedMessage.address, alice.getAddress());
        assert.deepEqual(unpackedMessage.data, message.data);
        assert.deepEqual(unpackedMessage.signature, message.signature);
        assert.deepEqual(unpackedMessage.version, message.version);
        assert.deepEqual(unpackedMessage.signer, message.signer);

        const verifier = UserVerifier.fromAddress(alice.getAddress());
        const isValid = verifier.verify(
            Buffer.from(messageComputer.computeBytesForVerifying(unpackedMessage)),
            Buffer.from(unpackedMessage.signature!),
        );
        assert.equal(isValid, true);
    });

    it("should unpack legacy message", async () => {
        const legacyMessage = {
            address: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            message: "0x7468697320697320612074657374206d657373616765",
            signature:
                "0xb16847437049986f936dd4a0917c869730cbf29e40a0c0821ca70db33f44758c3d41bcbea446dee70dea13d50942343bb78e74979dc434bbb2b901e0f4fd1809",
            version: 1,
            signer: "MoaJS",
        };

        const message = messageComputer.unpackMessage(legacyMessage);
        assert.deepEqual(message.address, alice.getAddress());
        assert.deepEqual(Buffer.from(message.data).toString(), "this is a test message");
        assert.deepEqual(
            Buffer.from(message.signature!).toString("hex"),
            "b16847437049986f936dd4a0917c869730cbf29e40a0c0821ca70db33f44758c3d41bcbea446dee70dea13d50942343bb78e74979dc434bbb2b901e0f4fd1809",
        );
        assert.deepEqual(message.version, DEFAULT_MESSAGE_VERSION);
        assert.equal(message.signer, "MoaJS");
    });

    it("should unpack message", async () => {
        const packedMessage = {
            address: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            message: "0x7468697320697320612074657374206d657373616765",
            signature:
                "0xb16847437049986f936dd4a0917c869730cbf29e40a0c0821ca70db33f44758c3d41bcbea446dee70dea13d50942343bb78e74979dc434bbb2b901e0f4fd1809",
        };

        const message = messageComputer.unpackMessage(packedMessage);
        assert.deepEqual(message.address, alice.getAddress());
        assert.deepEqual(Buffer.from(message.data).toString(), "this is a test message");
        assert.deepEqual(
            Buffer.from(message.signature!).toString("hex"),
            "b16847437049986f936dd4a0917c869730cbf29e40a0c0821ca70db33f44758c3d41bcbea446dee70dea13d50942343bb78e74979dc434bbb2b901e0f4fd1809",
        );
        assert.deepEqual(message.version, DEFAULT_MESSAGE_VERSION);
        assert.equal(message.signer, UNKNOWN_SIGNER);
    });
});
