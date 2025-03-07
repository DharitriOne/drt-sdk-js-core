import { assert } from "chai";
import { Address } from "../address";
import { TransactionVersion } from "../networkParams";
import { Signature } from "../signature";
import { loadTestWallets, TestWallet } from "../testutils";
import { TokenTransfer } from "../tokens";
import { Transaction } from "../transaction";
import { TransactionPayload } from "../transactionPayload";
import { ProtoSerializer } from "./serializer";
import { TransactionComputer } from "../transactionComputer";

describe("serialize transactions", () => {
    let wallets: Record<string, TestWallet>;
    let serializer = new ProtoSerializer();

    before(async function () {
        wallets = await loadTestWallets();
    });

    it("with no data, no value", async () => {
        let transaction = new Transaction({
            nonce: 89,
            value: 0,
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasLimit: 50000,
            chainID: "local-testnet",
        });

        const signer = wallets.alice.signer;
        transaction.applySignature(await signer.sign(transaction.serializeForSigning()));

        let buffer = serializer.serializeTransaction(transaction);
        assert.equal(
            buffer.toString("hex"),
            "0859120200001a208049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f82a200139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1388094ebdc0340d08603520d6c6f63616c2d746573746e657458026240de0b83647f9990b927ef9d3ff11ee0e6f2f50cc613c04c0e5b834f3e39eb0d2807cd664ce195713e1d9599e0a84cb56a400fe4e24e4e8d305e0d6dbc34597b0d",
        );
    });

    it("with data, no value", async () => {
        let transaction = new Transaction({
            nonce: 90,
            value: 0,
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
        });

        const signer = wallets.alice.signer;
        transaction.applySignature(await signer.sign(transaction.serializeForSigning()));

        let buffer = serializer.serializeTransaction(transaction);
        assert.equal(
            buffer.toString("hex"),
            "085a120200001a208049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f82a200139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1388094ebdc034080f1044a0568656c6c6f520d6c6f63616c2d746573746e65745802624025fc0da0e2e1be76a217072ef27cee8fee2b8fdaa4154b128ec7565cf6bec61bf9c1df3a495fce4bafb06a5ed0f0d5b38dab3eaeb11ed862255938ae9d4dcc05",
        );
    });

    it("with data, with value", async () => {
        let transaction = new Transaction({
            nonce: 91,
            value: TokenTransfer.rewaFromAmount(10),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasLimit: 100000,
            data: new TransactionPayload("for the book"),
            chainID: "local-testnet",
        });

        const signer = wallets.alice.signer;
        transaction.applySignature(await signer.sign(transaction.serializeForSigning()));

        let buffer = serializer.serializeTransaction(transaction);
        assert.equal(
            buffer.toString("hex"),
            "085b1209008ac7230489e800001a208049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f82a200139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1388094ebdc0340a08d064a0c666f722074686520626f6f6b520d6c6f63616c2d746573746e6574580262406e999fe472b03aaa98b62eb6c6ab17618575b883032f8b3c936d61eb06764ffe094fc0433fd7b61dbcd23a4af375e64e958aae8dfb6b9bd85084a8001b138001",
        );
    });

    it("with data, with large value", async () => {
        let transaction = new Transaction({
            nonce: 92,
            value: "123456789000000000000000000000",
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasLimit: 100000,
            data: new TransactionPayload("for the spaceship"),
            chainID: "local-testnet",
        });

        const signer = wallets.alice.signer;
        transaction.applySignature(await signer.sign(transaction.serializeForSigning()));

        let buffer = serializer.serializeTransaction(transaction);
        assert.equal(
            buffer.toString("hex"),
            "085c120e00018ee90ff6181f3761632000001a208049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f82a200139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1388094ebdc0340a08d064a11666f722074686520737061636573686970520d6c6f63616c2d746573746e6574580262401ff0a3e5da0b2e7d1160e8711456f5e1da865eb6607c0777511b621fac119e859ff900e7c56f0b0962c67edc75da10523ff5dc29a9b1ec8060685ad5dd1f3505",
        );
    });

    it("with nonce = 0", async () => {
        let transaction = new Transaction({
            nonce: 0,
            value: "0",
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
            version: new TransactionVersion(1),
        });

        transaction.applySignature(
            new Signature(
                "dfa3e9f2fdec60dcb353bac3b3435b4a2ff251e7e98eaf8620f46c731fc70c8ba5615fd4e208b05e75fe0f7dc44b7a99567e29f94fcd91efac7e67b182cd2a04",
            ),
        );

        let buffer = serializer.serializeTransaction(transaction);
        assert.equal(
            buffer.toString("hex"),
            "120200001a208049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f82a200139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1388094ebdc034080f1044a0568656c6c6f520d6c6f63616c2d746573746e657458016240dfa3e9f2fdec60dcb353bac3b3435b4a2ff251e7e98eaf8620f46c731fc70c8ba5615fd4e208b05e75fe0f7dc44b7a99567e29f94fcd91efac7e67b182cd2a04",
        );
    });

    it("with usernames", async () => {
        const transaction = new Transaction({
            nonce: 204,
            value: "1000000000000000000",
            sender: Address.fromBech32("moa1k2s324ww2g0yj38qn2ch2jwctdy8mnfxep94q9arncc6xecg3xaqhr5l9h"),
            receiver: Address.fromBech32("moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8"),
            senderUsername: "carol",
            receiverUsername: "alice",
            gasLimit: 50000,
            chainID: "T",
        });

        const signer = wallets.carol.signer;
        transaction.applySignature(await signer.sign(transaction.serializeForSigning()));

        const buffer = serializer.serializeTransaction(transaction);
        assert.equal(
            buffer.toString("hex"),
            "08cc011209000de0b6b3a76400001a200139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e12205616c6963652a20b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba32056361726f6c388094ebdc0340d08603520154580262403f3f645f9ac38142c1087a76b855e48ed0aa44185146df5f3317b8887e7b59f195d6093d3c2b30fb693a27e3175a199ef04a6e650101ab3f4b3649f0fe2f5204",
        );
    });

    it("serialize with inner transactions", async () => {
        const innerTransaction = new Transaction({
            nonce: 204,
            value: "1000000000000000000",
            sender: Address.fromBech32("moa1k2s324ww2g0yj38qn2ch2jwctdy8mnfxep94q9arncc6xecg3xaqhr5l9h"),
            receiver: Address.fromBech32("moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8"),
            senderUsername: "carol",
            receiverUsername: "alice",
            gasLimit: 50000,
            chainID: "T",
        });

        const signer = wallets.carol.signer;
        const txComputer = new TransactionComputer();
        innerTransaction.signature = await signer.sign(txComputer.computeBytesForSigning(innerTransaction));

        const relayedTransaction = new Transaction({
            nonce: 204,
            value: "1000000000000000000",
            sender: Address.fromBech32("moa1k2s324ww2g0yj38qn2ch2jwctdy8mnfxep94q9arncc6xecg3xaqhr5l9h"),
            receiver: Address.fromBech32("moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8"),
            senderUsername: "carol",
            receiverUsername: "alice",
            gasLimit: 50000,
            chainID: "T",
            relayer: wallets["carol"].address.toBech32(),
            innerTransactions: [innerTransaction],
        });

        relayedTransaction.signature = await signer.sign(txComputer.computeBytesForSigning(relayedTransaction));

        const serializedTransaction = serializer.serializeTransaction(relayedTransaction);
        assert.equal(
            serializedTransaction.toString("hex"),
            "08cc011209000de0b6b3a76400001a200139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e12205616c6963652a20b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba32056361726f6c388094ebdc0340d0860352015458026240986ea5f21a5b143b0e9a461599aa018d47165b79dfc7c3ee6768dcfa7aa67d2a647e8eaae545b7742dc0cb5ec1dd9d16705f6901be99eddb491fa90d1d4d240f820120b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba8a01b10108cc011209000de0b6b3a76400001a200139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e12205616c6963652a20b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba32056361726f6c388094ebdc0340d08603520154580262403f3f645f9ac38142c1087a76b855e48ed0aa44185146df5f3317b8887e7b59f195d6093d3c2b30fb693a27e3175a199ef04a6e650101ab3f4b3649f0fe2f5204",
        );
    });
});
