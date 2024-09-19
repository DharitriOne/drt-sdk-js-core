import { UserPublicKey, UserVerifier } from "@dharitri-sdk/wallet";
import BigNumber from "bignumber.js";
import { assert } from "chai";
import { Address } from "./address";
import { MIN_TRANSACTION_VERSION_THAT_SUPPORTS_OPTIONS } from "./constants";
import { TransactionOptions, TransactionVersion } from "./networkParams";
import { ProtoSerializer } from "./proto";
import { TestWallet, loadTestWallets } from "./testutils";
import { TokenTransfer } from "./tokens";
import { Transaction } from "./transaction";
import { TransactionComputer } from "./transactionComputer";
import { TransactionPayload } from "./transactionPayload";

describe("test transaction", async () => {
    let wallets: Record<string, TestWallet>;
    const minGasLimit = 50000;
    const minGasPrice = 1000000000;

    const transactionComputer = new TransactionComputer();

    const networkConfig = {
        MinGasLimit: 50000,
        GasPerDataByte: 1500,
        GasPriceModifier: 0.01,
        ChainID: "D",
    };

    before(async function () {
        wallets = await loadTestWallets();
    });

    it("should serialize transaction for signing (without data)", async () => {
        const transaction = new Transaction({
            chainID: networkConfig.ChainID,
            sender: wallets.alice.address.bech32(),
            receiver: wallets.bob.address.bech32(),
            gasLimit: 50000n,
            value: 0n,
            version: 2,
            nonce: 89n,
        });

        const serializedTransactionBytes = transactionComputer.computeBytesForSigning(transaction);
        const serializedTransaction = Buffer.from(serializedTransactionBytes).toString();

        assert.equal(
            serializedTransaction,
            `{"nonce":89,"value":"0","receiver":"moa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruq0yu4wk","sender":"moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8","gasPrice":1000000000,"gasLimit":50000,"chainID":"D","version":2}`,
        );
    });

    it("should serialize transaction for signing (with data)", async () => {
        const transaction = new Transaction({
            chainID: networkConfig.ChainID,
            sender: wallets.alice.address.bech32(),
            receiver: wallets.bob.address.bech32(),
            gasLimit: 70000n,
            value: 1000000000000000000n,
            version: 2,
            nonce: 90n,
            data: new Uint8Array(Buffer.from("hello")),
        });

        const serializedTransactionBytes = transactionComputer.computeBytesForSigning(transaction);
        const serializedTransaction = Buffer.from(serializedTransactionBytes).toString();

        assert.equal(
            serializedTransaction,
            `{"nonce":90,"value":"1000000000000000000","receiver":"moa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruq0yu4wk","sender":"moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8","gasPrice":1000000000,"gasLimit":70000,"data":"aGVsbG8=","chainID":"D","version":2}`,
        );
    });

    it("should sign transaction (with no data, no value) (legacy)", async () => {
        const transaction = new Transaction({
            nonce: 89,
            value: "0",
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: minGasLimit,
            chainID: "local-testnet",
        });

        transaction.applySignature(await wallets.alice.signer.sign(transaction.serializeForSigning()));

        assert.equal(
            transaction.getSignature().toString("hex"),
            "de0b83647f9990b927ef9d3ff11ee0e6f2f50cc613c04c0e5b834f3e39eb0d2807cd664ce195713e1d9599e0a84cb56a400fe4e24e4e8d305e0d6dbc34597b0d",
        );
        assert.equal(
            transaction.getHash().toString(),
            "c5f121c9d62f1ea9af1039f3874fe12e6909864018784a51b6b4e9fa054c3042",
        );
    });

    it("should sign transaction (with data, no value) (legacy)", async () => {
        const transaction = new Transaction({
            nonce: 90,
            value: "0",
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
        });

        transaction.applySignature(await wallets.alice.signer.sign(transaction.serializeForSigning()));

        assert.equal(
            transaction.getSignature().toString("hex"),
            "25fc0da0e2e1be76a217072ef27cee8fee2b8fdaa4154b128ec7565cf6bec61bf9c1df3a495fce4bafb06a5ed0f0d5b38dab3eaeb11ed862255938ae9d4dcc05",
        );
        assert.equal(
            transaction.getHash().toString(),
            "670db36646b636defc117840da59448b26baf45ddac1ba60b14b6eb1557b0198",
        );
    });

    it("should sign transaction (with usernames)", async () => {
        const transaction = new Transaction({
            chainID: "T",
            sender: wallets.carol.address.bech32(),
            receiver: wallets.alice.address.bech32(),
            gasLimit: 50000n,
            value: 1000000000000000000n,
            version: 2,
            nonce: 204n,
            senderUsername: "carol",
            receiverUsername: "alice",
        });

        transaction.signature = await wallets.carol.signer.sign(
            transactionComputer.computeBytesForSigning(transaction),
        );

        assert.equal(
            Buffer.from(transaction.signature).toString("hex"),
            "3f3f645f9ac38142c1087a76b855e48ed0aa44185146df5f3317b8887e7b59f195d6093d3c2b30fb693a27e3175a199ef04a6e650101ab3f4b3649f0fe2f5204",
        );
    });

    it("should compute hash", async () => {
        const transaction = new Transaction({
            chainID: networkConfig.ChainID,
            sender: wallets.alice.address.bech32(),
            receiver: wallets.alice.address.bech32(),
            gasLimit: 100000n,
            value: 1000000000000n,
            version: 2,
            nonce: 17243n,
            data: Buffer.from("testtx"),
        });

        transaction.signature = Buffer.from(
            "eaa9e4dfbd21695d9511e9754bde13e90c5cfb21748a339a79be11f744c71872e9fe8e73c6035c413f5f08eef09e5458e9ea6fc315ff4da0ab6d000b450b2a07",
            "hex",
        );

        const hash = transactionComputer.computeTransactionHash(transaction);

        assert.equal(
            Buffer.from(hash).toString("hex"),
            "169b76b752b220a76a93aeebc462a1192db1dc2ec9d17e6b4d7b0dcc91792f03",
        );
    });

    it("should compute hash (with usernames)", async () => {
        const transaction = new Transaction({
            chainID: networkConfig.ChainID,
            sender: wallets.alice.address.bech32(),
            receiver: wallets.alice.address.bech32(),
            gasLimit: 100000n,
            value: 1000000000000n,
            version: 2,
            nonce: 17244n,
            data: Buffer.from("testtx"),
            senderUsername: "alice",
            receiverUsername: "alice",
        });

        transaction.signature = Buffer.from(
            "807bcd7de5553ea6dfc57c0510e84d46813c5963d90fec50991c500091408fcf6216dca48dae16a579a1611ed8b2834bae8bd0027dc17eb557963f7151b82c07",
            "hex",
        );

        const hash = transactionComputer.computeTransactionHash(transaction);

        assert.equal(
            Buffer.from(hash).toString("hex"),
            "41b5acf7ebaf4a9165a64206b6ebc02021b3adda55ffb2a2698aac2e7004dc29",
        );
    });

    it("should sign & compute hash (with data, with opaque, unused options) (legacy)", async () => {
        const transaction = new Transaction({
            nonce: 89,
            value: "0",
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: minGasLimit,
            chainID: "local-testnet",
            // The protocol ignores the options when version == 1
            version: new TransactionVersion(1),
            options: new TransactionOptions(1),
        });

        assert.throws(() => {
            transaction.serializeForSigning();
        }, `Non-empty transaction options requires transaction version >= ${MIN_TRANSACTION_VERSION_THAT_SUPPORTS_OPTIONS}`);
    });

    it("should sign & compute hash (with data, with value) (legacy)", async () => {
        const transaction = new Transaction({
            nonce: 91,
            value: TokenTransfer.rewaFromAmount(10),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: 100000,
            data: new TransactionPayload("for the book"),
            chainID: "local-testnet",
        });

        transaction.applySignature(await wallets.alice.signer.sign(transaction.serializeForSigning()));

        assert.equal(
            transaction.getSignature().toString("hex"),
            "6e999fe472b03aaa98b62eb6c6ab17618575b883032f8b3c936d61eb06764ffe094fc0433fd7b61dbcd23a4af375e64e958aae8dfb6b9bd85084a8001b138001",
        );
        assert.equal(
            transaction.getHash().toString(),
            "52897f5f472214e054b7588da44d528bdc6fbbbd6e0ede67b67316feeba7145a",
        );
    });

    it("should sign & compute hash (with data, with large value) (legacy)", async () => {
        const transaction = new Transaction({
            nonce: 92,
            value: TokenTransfer.rewaFromBigInteger("123456789000000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: 100000,
            data: new TransactionPayload("for the spaceship"),
            chainID: "local-testnet",
        });

        transaction.applySignature(await wallets.alice.signer.sign(transaction.serializeForSigning()));

        assert.equal(
            transaction.getSignature().toString("hex"),
            "1ff0a3e5da0b2e7d1160e8711456f5e1da865eb6607c0777511b621fac119e859ff900e7c56f0b0962c67edc75da10523ff5dc29a9b1ec8060685ad5dd1f3505",
        );
        assert.equal(
            transaction.getHash().toString(),
            "c57dfcb377fad1db5fd36e1291823d6361d0361b2791e9cf83c1991676679069",
        );
    });

    it("should sign & compute hash (with nonce = 0) (legacy)", async () => {
        const transaction = new Transaction({
            nonce: 0,
            value: 0,
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
            version: new TransactionVersion(1),
        });

        transaction.applySignature(await wallets.alice.signer.sign(transaction.serializeForSigning()));

        assert.equal(
            transaction.getSignature().toString("hex"),
            "d73e9c2f978d248eaba41c2453088f0e3488c02eb88ede7b1f40a22527a0f90c747056163a1625c127b3b6bd602a3a0cb607478a45d0a847e471911b3b87e805",
        );
        assert.equal(
            transaction.getHash().toString(),
            "18361f53a01d70faa43b563c0da4ea95444abe85ffdce980131cee26cd7ba06d",
        );
    });

    it("should sign & compute hash (without options field, should be omitted) (legacy)", async () => {
        const transaction = new Transaction({
            nonce: 89,
            value: 0,
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: minGasLimit,
            chainID: "local-testnet",
        });

        transaction.applySignature(await wallets.alice.signer.sign(transaction.serializeForSigning()));

        assert.equal(
            transaction.getSignature().toString("hex"),
            "de0b83647f9990b927ef9d3ff11ee0e6f2f50cc613c04c0e5b834f3e39eb0d2807cd664ce195713e1d9599e0a84cb56a400fe4e24e4e8d305e0d6dbc34597b0d",
        );
        assert.equal(
            transaction.getHash().toString(),
            "c5f121c9d62f1ea9af1039f3874fe12e6909864018784a51b6b4e9fa054c3042",
        );

        const result = transaction.serializeForSigning();
        assert.isFalse(result.toString().includes("options"));
    });

    it("should sign & compute hash (with guardian field, should be omitted) (legacy)", async () => {
        const transaction = new Transaction({
            nonce: 89,
            value: 0,
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: minGasLimit,
            chainID: "local-testnet",
        });

        transaction.applySignature(await wallets.alice.signer.sign(transaction.serializeForSigning()));

        assert.equal(
            transaction.getSignature().toString("hex"),
            "de0b83647f9990b927ef9d3ff11ee0e6f2f50cc613c04c0e5b834f3e39eb0d2807cd664ce195713e1d9599e0a84cb56a400fe4e24e4e8d305e0d6dbc34597b0d",
        );
        assert.equal(
            transaction.getHash().toString(),
            "c5f121c9d62f1ea9af1039f3874fe12e6909864018784a51b6b4e9fa054c3042",
        );

        const result = transaction.serializeForSigning();
        assert.isFalse(result.toString().includes("options"));
    });

    it("should sign & compute hash (with usernames) (legacy)", async () => {
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

        transaction.applySignature(await wallets.carol.signer.sign(transaction.serializeForSigning()));

        assert.equal(
            transaction.getSignature().toString("hex"),
            "3f3f645f9ac38142c1087a76b855e48ed0aa44185146df5f3317b8887e7b59f195d6093d3c2b30fb693a27e3175a199ef04a6e650101ab3f4b3649f0fe2f5204",
        );
        assert.equal(
            transaction.getHash().toString(),
            "cb8f560d2ee684d9a496843875227d04637e55b3189ad09c389f69dec92b8f6a",
        );
    });

    it("should sign & compute hash (guarded transaction)", async () => {
        const alice = wallets.alice;

        const transaction = new Transaction({
            chainID: "local-testnet",
            sender: alice.address.bech32(),
            receiver: wallets.bob.address.bech32(),
            gasLimit: 150000n,
            gasPrice: 1000000000n,
            data: new Uint8Array(Buffer.from("test data field")),
            version: 2,
            options: 2,
            nonce: 92n,
            value: 123456789000000000000000000000n,
            guardian: "moa1x23lzn8483xs2su4fak0r0dqx6w38enpmmqf2yrkylwq7mfnvyhstcgmz5",
        });
        transaction.guardianSignature = new Uint8Array(64);
        transaction.signature = await alice.signer.sign(transactionComputer.computeBytesForSigning(transaction));

        const serializer = new ProtoSerializer();
        const buffer = serializer.serializeTransaction(transaction);

        assert.equal(
            buffer.toString("hex"),
            "085c120e00018ee90ff6181f3761632000001a208049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f82a200139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1388094ebdc0340f093094a0f746573742064617461206669656c64520d6c6f63616c2d746573746e657458026240c74c3e5b276c32ae72ab1a0bac17939d7577e55e1467cd3b4d4a45b04ad3957e94a855657b42601384819502882d559dd5f8e31a93097e113fe9fa82615151046802722032a3f14cf53c4d0543954f6cf1bda0369d13e661dec095107627dc0f6d33612f7a4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );

        const txHash = transactionComputer.computeTransactionHash(transaction);
        assert.equal(
            Buffer.from(txHash).toString("hex"),
            "0896751a0c0eb3316041295ae1d71a4200aef5b359609b0cc181cae4e22b531e",
        );
    });

    it("computes fee (legacy)", () => {
        const transaction = new Transaction({
            nonce: 92,
            value: TokenTransfer.rewaFromBigInteger("123456789000000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: minGasLimit,
            chainID: "local-testnet",
        });

        const fee = transaction.computeFee(networkConfig);
        assert.equal(fee.toString(), "50000000000000");
    });

    it("computes fee", async () => {
        const transaction = new Transaction({
            chainID: "D",
            sender: wallets.alice.address.bech32(),
            receiver: wallets.alice.address.bech32(),
            gasLimit: 50000n,
            gasPrice: minGasPrice,
        });

        const gasLimit = transactionComputer.computeTransactionFee(transaction, networkConfig);
        assert.equal(gasLimit.toString(), "50000000000000");
    });

    it("computes fee, but should throw `NotEnoughGas` error", async () => {
        const transaction = new Transaction({
            chainID: networkConfig.ChainID,
            sender: wallets.alice.address.bech32(),
            receiver: wallets.alice.address.bech32(),
            gasLimit: 50000n,
            data: Buffer.from("toolittlegaslimit"),
        });

        assert.throws(() => {
            transactionComputer.computeTransactionFee(transaction, networkConfig);
        });
    });

    it("computes fee (with data field) (legacy)", () => {
        let transaction = new Transaction({
            nonce: 92,
            value: TokenTransfer.rewaFromBigInteger("123456789000000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            data: new TransactionPayload("testdata"),
            gasPrice: minGasPrice,
            gasLimit: minGasLimit + 12010,
            chainID: "local-testnet",
        });

        let fee = transaction.computeFee(networkConfig);
        assert.equal(fee.toString(), "62000100000000");
    });

    it("computes fee (with data field)", async () => {
        const transaction = new Transaction({
            chainID: networkConfig.ChainID,
            sender: wallets.alice.address.bech32(),
            receiver: wallets.alice.address.bech32(),
            gasLimit: 50000n + 12010n,
            gasPrice: minGasPrice,
            data: Buffer.from("testdata"),
        });

        const gasLimit = transactionComputer.computeTransactionFee(transaction, networkConfig);
        assert.equal(gasLimit.toString(), "62000100000000");
    });

    it("should convert transaction to plain object and back", () => {
        const sender = wallets.alice.address;
        const transaction = new Transaction({
            nonce: 90,
            value: "123456789000000000000000000000",
            sender: sender,
            receiver: wallets.bob.address,
            senderUsername: "alice",
            receiverUsername: "bob",
            gasPrice: minGasPrice,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
        });

        const plainObject = transaction.toPlainObject();
        const restoredTransaction = Transaction.fromPlainObject(plainObject);
        assert.deepEqual(restoredTransaction, transaction);
    });

    it("should handle large values", () => {
        const tx1 = new Transaction({
            value: "123456789000000000000000000000",
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasLimit: 50000,
            chainID: "local-testnet",
        });
        assert.equal(tx1.getValue().toString(), "123456789000000000000000000000");

        const tx2 = new Transaction({
            value: TokenTransfer.rewaFromBigInteger("123456789000000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasLimit: 50000,
            chainID: "local-testnet",
        });
        assert.equal(tx2.getValue().toString(), "123456789000000000000000000000");

        const tx3 = new Transaction({
            // Passing a BigNumber is not recommended.
            // However, ITransactionValue interface is permissive, and developers may mistakenly pass such objects as values.
            // TokenTransfer objects or simple strings (see above) are preferred, instead.
            value: new BigNumber("123456789000000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasLimit: 50000,
            chainID: "local-testnet",
        });
        assert.equal(tx3.getValue().toString(), "123456789000000000000000000000");
    });

    it("checks correctly the version and options of the transaction", async () => {
        let transaction = new Transaction({
            nonce: 90,
            value: new BigNumber("1000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
            version: new TransactionVersion(1),
            options: TransactionOptions.withDefaultOptions(),
        });
        assert.isFalse(transaction.isGuardedTransaction());

        transaction = new Transaction({
            nonce: 90,
            value: new BigNumber("1000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
            version: new TransactionVersion(1),
            options: TransactionOptions.withOptions({ guarded: true }),
        });
        assert.isFalse(transaction.isGuardedTransaction());

        transaction = new Transaction({
            nonce: 90,
            value: new BigNumber("1000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
            version: new TransactionVersion(2),
            options: TransactionOptions.withOptions({ guarded: true }),
        });
        assert.isFalse(transaction.isGuardedTransaction());

        transaction = new Transaction({
            nonce: 90,
            value: new BigNumber("1000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
            version: new TransactionVersion(2),
            options: TransactionOptions.withOptions({ guarded: true }),
        });
        assert.isFalse(transaction.isGuardedTransaction());

        transaction = new Transaction({
            nonce: 90,
            value: new BigNumber("1000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            guardian: wallets.bob.address,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
            version: new TransactionVersion(2),
            options: TransactionOptions.withOptions({ guarded: true }),
        });
        assert.isFalse(transaction.isGuardedTransaction());

        transaction = new Transaction({
            nonce: 90,
            value: new BigNumber("1000000000000000000"),
            sender: wallets.alice.address,
            receiver: wallets.bob.address,
            gasPrice: minGasPrice,
            guardian: wallets.bob.address,
            gasLimit: 80000,
            data: new TransactionPayload("hello"),
            chainID: "local-testnet",
            version: new TransactionVersion(2),
            options: TransactionOptions.withOptions({ guarded: true }),
        });
        transaction.applySignature(await wallets.alice.signer.sign(transaction.serializeForSigning()));
        transaction.applyGuardianSignature(transaction.getSignature());
        assert.isTrue(transaction.isGuardedTransaction());
    });

    it("test sign using hash", async () => {
        let transaction = new Transaction({
            nonce: 89n,
            value: 0n,
            sender: wallets.alice.address.toBech32(),
            receiver: wallets.bob.address.toBech32(),
            gasLimit: 50000n,
            gasPrice: 1000000000n,
            chainID: "integration tests chain ID",
            version: 2,
            options: 1,
        });

        transaction.signature = await wallets.alice.signer.sign(transactionComputer.computeHashForSigning(transaction));

        assert.equal(
            "e55e641a75b4357269bb576ec597aac8ef9650c8d37a75d4fc6c67ef78703e9dc8de17dca8a3b207610e202a3faea80f92f6e5b7b95d4fb91136d97c9167dc08",
            Buffer.from(transaction.signature).toString("hex"),
        );
    });

    it("should apply guardian", async () => {
        let transaction = new Transaction({
            nonce: 89n,
            value: 0n,
            sender: wallets.alice.address.toBech32(),
            receiver: wallets.bob.address.toBech32(),
            gasLimit: 50000n,
            chainID: "localnet",
        });

        transactionComputer.applyGuardian(transaction, wallets.carol.address.toBech32());

        assert.equal(transaction.version, 2);
        assert.equal(transaction.options, 2);
        assert.equal(transaction.guardian, wallets.carol.address.toBech32());
    });

    it("should apply guardian with options set for hash signing", async () => {
        let transaction = new Transaction({
            nonce: 89n,
            value: 0n,
            sender: wallets.alice.address.toBech32(),
            receiver: wallets.bob.address.toBech32(),
            gasLimit: 50000n,
            chainID: "localnet",
            version: 1,
        });

        transactionComputer.applyOptionsForHashSigning(transaction);
        assert.equal(transaction.version, 2);
        assert.equal(transaction.options, 1);

        transactionComputer.applyGuardian(transaction, wallets.carol.address.toBech32());
        assert.equal(transaction.version, 2);
        assert.equal(transaction.options, 3);
    });

    it("should ensure transaction is valid", async () => {
        let transaction = new Transaction({
            sender: "invalidAddress",
            receiver: wallets.bob.address.toBech32(),
            gasLimit: 50000n,
            chainID: "",
        });

        transaction.sender = wallets.alice.address.toBech32();

        assert.throws(() => {
            transactionComputer.computeBytesForSigning(transaction);
        }, "The `chainID` field is not set");

        transaction.chainID = "localnet";
        transaction.version = 1;
        transaction.options = 2;

        assert.throws(() => {
            transactionComputer.computeBytesForSigning(transaction);
        }, `Non-empty transaction options requires transaction version >= ${MIN_TRANSACTION_VERSION_THAT_SUPPORTS_OPTIONS}`);

        transactionComputer.applyOptionsForHashSigning(transaction);

        assert.equal(transaction.version, 2);
        assert.equal(transaction.options, 3);
    });

    it("should compute bytes to verify transaction signature", async () => {
        let transaction = new Transaction({
            sender: wallets.alice.address.toBech32(),
            receiver: wallets.bob.address.toBech32(),
            gasLimit: 50000n,
            chainID: "D",
            nonce: 7n,
        });

        transaction.signature = await wallets.alice.signer.sign(
            transactionComputer.computeBytesForSigning(transaction),
        );

        const userVerifier = new UserVerifier(new UserPublicKey(wallets.alice.address.getPublicKey()));
        const isSignedByAlice = userVerifier.verify(
            transactionComputer.computeBytesForVerifying(transaction),
            transaction.signature,
        );

        const wrongVerifier = new UserVerifier(new UserPublicKey(wallets.bob.address.getPublicKey()));
        const isSignedByBob = wrongVerifier.verify(
            transactionComputer.computeBytesForVerifying(transaction),
            transaction.signature,
        );

        assert.equal(isSignedByAlice, true);
        assert.equal(isSignedByBob, false);
    });

    it("should compute bytes to verify transaction signature (signed by hash)", async () => {
        let transaction = new Transaction({
            sender: wallets.alice.address.toBech32(),
            receiver: wallets.bob.address.toBech32(),
            gasLimit: 50000n,
            chainID: "D",
            nonce: 7n,
        });

        transactionComputer.applyOptionsForHashSigning(transaction);

        transaction.signature = await wallets.alice.signer.sign(transactionComputer.computeHashForSigning(transaction));

        const userVerifier = new UserVerifier(new UserPublicKey(wallets.alice.address.getPublicKey()));
        const isSignedByAlice = userVerifier.verify(
            transactionComputer.computeBytesForVerifying(transaction),
            transaction.signature,
        );

        const wrongVerifier = new UserVerifier(new UserPublicKey(wallets.bob.address.getPublicKey()));
        const isSignedByBob = wrongVerifier.verify(
            transactionComputer.computeBytesForVerifying(transaction),
            transaction.signature,
        );

        assert.equal(isSignedByAlice, true);
        assert.equal(isSignedByBob, false);
    });
});
