import { assert } from "chai";
import { TestWallet, loadTestWallets } from "../testutils";
import { Transaction } from "../transaction";
import { TransactionComputer } from "../transactionComputer";
import { RelayedTransactionsFactory } from "./relayedTransactionsFactory";
import { TransactionsFactoryConfig } from "./transactionsFactoryConfig";

describe("test relayed transactions factory", function () {
    const config = new TransactionsFactoryConfig({ chainID: "T" });
    const factory = new RelayedTransactionsFactory({ config: config });
    const transactionComputer = new TransactionComputer();
    let alice: TestWallet, bob: TestWallet, carol: TestWallet, grace: TestWallet, frank: TestWallet;

    before(async function () {
        ({ alice, bob, carol, grace, frank } = await loadTestWallets());
    });

    it("should throw exception when creating relayed v1 transaction with invalid inner transaction", async function () {
        let innerTransaction = new Transaction({
            sender: alice.address.bech32(),
            receiver: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            gasLimit: 10000000n,
            data: Buffer.from("getContractConfig"),
            chainID: config.chainID,
        });

        assert.throws(() => {
            factory.createRelayedV1Transaction({ innerTransaction: innerTransaction, relayerAddress: bob.address }),
                "The inner transaction is not signed";
        });

        innerTransaction.gasLimit = 0n;
        innerTransaction.signature = Buffer.from("invalidsignature");

        assert.throws(() => {
            factory.createRelayedV1Transaction({ innerTransaction: innerTransaction, relayerAddress: bob.address }),
                "The gas limit is not set for the inner transaction";
        });
    });

    it("should create relayed v1 transaction", async function () {
        let innerTransaction = new Transaction({
            sender: bob.address.bech32(),
            receiver: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            gasLimit: 60000000n,
            data: Buffer.from("getContractConfig"),
            chainID: config.chainID,
            nonce: 198n,
        });

        const serializedInnerTransaction = transactionComputer.computeBytesForSigning(innerTransaction);
        innerTransaction.signature = await bob.signer.sign(serializedInnerTransaction);

        const relayedTransaction = factory.createRelayedV1Transaction({
            innerTransaction: innerTransaction,
            relayerAddress: alice.address,
        });
        relayedTransaction.nonce = 2627n;

        const serializedRelayedTransaction = transactionComputer.computeBytesForSigning(relayedTransaction);
        relayedTransaction.signature = await alice.signer.sign(serializedRelayedTransaction);

        assert.equal(
            Buffer.from(relayedTransaction.data).toString(),
            "relayedTx@7b226e6f6e6365223a3139382c2273656e646572223a2267456e574f65576d6d413063306a6b71764d354241707a61644b46574e534f69417643575163776d4750673d222c227265636569766572223a22414141414141414141414141415141414141414141414141414141414141414141414141414141432f2f383d222c2276616c7565223a302c226761735072696365223a313030303030303030302c226761734c696d6974223a36303030303030302c2264617461223a225a3256305132397564484a68593352446232356d6157633d222c227369676e6174757265223a22746264506468326e45757a317973436e414b724c3573386253576e4865304142326434735a4f365253794434315a516f4a69434d346430543762356976587a456475346579595468462f30617a6e41614363354442413d3d222c22636861696e4944223a2256413d3d222c2276657273696f6e223a327d",
        );
        assert.equal(
            Buffer.from(relayedTransaction.signature).toString("hex"),
            "71c43095b3289582e8f6fbb1b38fc3a42a2bf091944a4ed64756bf8dd17738dabf9a32da7450e313e7bcec53c6f11d639d6bec79bbd6975841a9517eecd4b207",
        );
    });

    it("should create relayed v1 transaction with usernames", async function () {
        let innerTransaction = new Transaction({
            sender: carol.address.bech32(),
            receiver: alice.address.bech32(),
            gasLimit: 50000n,
            chainID: config.chainID,
            nonce: 208n,
            senderUsername: "carol",
            receiverUsername: "alice",
            value: 1000000000000000000n,
        });

        const serializedInnerTransaction = transactionComputer.computeBytesForSigning(innerTransaction);
        innerTransaction.signature = await carol.signer.sign(serializedInnerTransaction);

        const relayedTransaction = factory.createRelayedV1Transaction({
            innerTransaction: innerTransaction,
            relayerAddress: frank.address,
        });
        relayedTransaction.nonce = 715n;

        const serializedRelayedTransaction = transactionComputer.computeBytesForSigning(relayedTransaction);
        relayedTransaction.signature = await frank.signer.sign(serializedRelayedTransaction);

        assert.equal(
            Buffer.from(relayedTransaction.data).toString(),
            "relayedTx@7b226e6f6e6365223a3230382c2273656e646572223a227371455656633553486b6c45344a717864556e59573068397a536249533141586f3534786f32634969626f3d222c227265636569766572223a2241546c484c76396f686e63616d433877673970645168386b77704742356a6949496f3349484b594e6165453d222c2276616c7565223a313030303030303030303030303030303030302c226761735072696365223a313030303030303030302c226761734c696d6974223a35303030302c2264617461223a22222c227369676e6174757265223a226b702f6f36652b4f666334722f42667545436b446850666330546d52663578622f736665637a487968416f414479763156696a6d6346337a68632f766e7839774c36426e586451384f4c62526e3436537947557743413d3d222c22636861696e4944223a2256413d3d222c2276657273696f6e223a322c22736e64557365724e616d65223a22593246796232773d222c22726376557365724e616d65223a22595778705932553d227d",
        );
        assert.equal(
            Buffer.from(relayedTransaction.signature).toString("hex"),
            "aae9b37b80a61e80a86011b4f61fb50a98d23b49bb4899ca962f1c085234a1cb45dfeb509bfcba075c32452d6906b227f99d1c4ffb946df542c644b4b70a9808",
        );
    });

    it("should create relayed v1 transaction with big value", async function () {
        let innerTransaction = new Transaction({
            sender: carol.address.bech32(),
            receiver: alice.address.bech32(),
            gasLimit: 50000n,
            chainID: config.chainID,
            nonce: 208n,
            senderUsername: "carol",
            receiverUsername: "alice",
            value: 1999999000000000000000000n,
        });

        const serializedInnerTransaction = transactionComputer.computeBytesForSigning(innerTransaction);
        innerTransaction.signature = await carol.signer.sign(serializedInnerTransaction);

        const relayedTransaction = factory.createRelayedV1Transaction({
            innerTransaction: innerTransaction,
            relayerAddress: frank.address,
        });
        relayedTransaction.nonce = 715n;

        const serializedRelayedTransaction = transactionComputer.computeBytesForSigning(relayedTransaction);
        relayedTransaction.signature = await frank.signer.sign(serializedRelayedTransaction);

        assert.equal(
            Buffer.from(relayedTransaction.data).toString(),
            "relayedTx@7b226e6f6e6365223a3230382c2273656e646572223a227371455656633553486b6c45344a717864556e59573068397a536249533141586f3534786f32634969626f3d222c227265636569766572223a2241546c484c76396f686e63616d433877673970645168386b77704742356a6949496f3349484b594e6165453d222c2276616c7565223a313939393939393030303030303030303030303030303030302c226761735072696365223a313030303030303030302c226761734c696d6974223a35303030302c2264617461223a22222c227369676e6174757265223a224a364262347457786c736a4d49433237437830487054467550677335636e496c74773253734a635754746b2f4b4b77444b794455466a64594e734b2b4c4b58615859562f4d4c4d422f647462584772684c32737844513d3d222c22636861696e4944223a2256413d3d222c2276657273696f6e223a322c22736e64557365724e616d65223a22593246796232773d222c22726376557365724e616d65223a22595778705932553d227d",
        );
        assert.equal(
            Buffer.from(relayedTransaction.signature).toString("hex"),
            "f416ddfe2af027f3b3d1c2d6e0070138f62dfe7b21ad165d97f0830128ee563946424a60480ee802a46c353d4462af1d1355a1d979fd4116a4e3b3595ab97600",
        );
    });

    it("should create relayed v1 transaction with guarded inner transaction", async function () {
        let innerTransaction = new Transaction({
            sender: bob.address.bech32(),
            receiver: "moa1qqqqqqqqqqqqqpgq54tsxmej537z9leghvp69hfu4f8gg5eu396q2fwu0j",
            gasLimit: 60000000n,
            chainID: config.chainID,
            data: Buffer.from("getContractConfig"),
            nonce: 198n,
            version: 2,
            options: 2,
            guardian: grace.address.bech32(),
        });

        const serializedInnerTransaction = transactionComputer.computeBytesForSigning(innerTransaction);
        innerTransaction.signature = await bob.signer.sign(serializedInnerTransaction);
        innerTransaction.guardianSignature = await grace.signer.sign(serializedInnerTransaction);

        const relayedTransaction = factory.createRelayedV1Transaction({
            innerTransaction: innerTransaction,
            relayerAddress: alice.address,
        });
        relayedTransaction.nonce = 2627n;

        const serializedRelayedTransaction = transactionComputer.computeBytesForSigning(relayedTransaction);
        relayedTransaction.signature = await alice.signer.sign(serializedRelayedTransaction);

        assert.equal(
            Buffer.from(relayedTransaction.data).toString(),
            "relayedTx@7b226e6f6e6365223a3139382c2273656e646572223a2267456e574f65576d6d413063306a6b71764d354241707a61644b46574e534f69417643575163776d4750673d222c227265636569766572223a22414141414141414141414146414b565841323879704877692f79693741364c64504b704f68464d386958513d222c2276616c7565223a302c226761735072696365223a313030303030303030302c226761734c696d6974223a36303030303030302c2264617461223a225a3256305132397564484a68593352446232356d6157633d222c227369676e6174757265223a22617748304e2b4866704c49346968726374446b56426b33636b575949756656384d7536596e706c7147566239705447584f6f776c375231306a77316f5161545778595573374d41756353784c6e6c616b7378554541773d3d222c22636861696e4944223a2256413d3d222c2276657273696f6e223a322c226f7074696f6e73223a322c22677561726469616e223a22486f714c61306e655733766843716f56696c70715372744c5673774939535337586d7a563868477450684d3d222c22677561726469616e5369676e6174757265223a224252306a414e69706a32796d4466694b426a364e757034454948652f5972383971687a443374453565556670626638503870506159376a44614779514e66735159776f4f4b58414b4873644b5a4557336672427743773d3d227d",
        );
        assert.equal(
            Buffer.from(relayedTransaction.signature).toString("hex"),
            "86a1dfafd0a0139f3a0cd24f51f396cd2a573c061c10b13619b2f4ba137c40fbd890559fd65bf941a52cf085244f2af2a139ef2817d15d5c0d1eb7d0dd8a910d",
        );
    });

    it("should create guarded relayed v1 transaction with guarded inner transaction", async function () {
        let innerTransaction = new Transaction({
            sender: bob.address.bech32(),
            receiver: "moa1qqqqqqqqqqqqqpgq54tsxmej537z9leghvp69hfu4f8gg5eu396q2fwu0j",
            gasLimit: 60000000n,
            chainID: config.chainID,
            data: Buffer.from("addNumber"),
            nonce: 198n,
            version: 2,
            options: 2,
            guardian: grace.address.bech32(),
        });

        const serializedInnerTransaction = transactionComputer.computeBytesForSigning(innerTransaction);
        innerTransaction.signature = await bob.signer.sign(serializedInnerTransaction);
        innerTransaction.guardianSignature = await grace.signer.sign(serializedInnerTransaction);

        const relayedTransaction = factory.createRelayedV1Transaction({
            innerTransaction: innerTransaction,
            relayerAddress: alice.address,
        });
        relayedTransaction.nonce = 2627n;
        relayedTransaction.options = 2;
        relayedTransaction.guardian = frank.address.bech32();

        const serializedRelayedTransaction = transactionComputer.computeBytesForSigning(relayedTransaction);
        relayedTransaction.signature = await alice.signer.sign(serializedRelayedTransaction);
        relayedTransaction.guardianSignature = await frank.signer.sign(serializedRelayedTransaction);

        assert.equal(
            Buffer.from(relayedTransaction.data).toString(),
            "relayedTx@7b226e6f6e6365223a3139382c2273656e646572223a2267456e574f65576d6d413063306a6b71764d354241707a61644b46574e534f69417643575163776d4750673d222c227265636569766572223a22414141414141414141414146414b565841323879704877692f79693741364c64504b704f68464d386958513d222c2276616c7565223a302c226761735072696365223a313030303030303030302c226761734c696d6974223a36303030303030302c2264617461223a225957526b546e5674596d5679222c227369676e6174757265223a226e6a6a7678546353775756396a7a68722b55367041556c3549586d614158762f395648394b4554414a4f493172426b565169536c38442f7962535955634a484b4e6954686243325767796d6b4f564b624a4b6d4442773d3d222c22636861696e4944223a2256413d3d222c2276657273696f6e223a322c226f7074696f6e73223a322c22677561726469616e223a22486f714c61306e655733766843716f56696c70715372744c5673774939535337586d7a563868477450684d3d222c22677561726469616e5369676e6174757265223a22492b4a544753686f696a432f483366557a4c79522f44534b31457135746f79392b796b457554444335746c53765a61577543435a76667a6a704a7872636e5868316e5178453376434a2f7947753836677270583841513d3d227d",
        );
        assert.equal(
            Buffer.from(relayedTransaction.signature).toString("hex"),
            "46b0383b43e39948ba78bc63e60dae5d1177b6d5e371578ebcc16f3196a18068b8671c5ff3ca3d42a4f378ec509f72db89a4b55b0b15224f44d53a4fed286604",
        );
    });

    it("should throw exception when creating relayed v2 transaction with invalid inner transaction", async function () {
        let innerTransaction = new Transaction({
            sender: bob.address.bech32(),
            receiver: bob.address.bech32(),
            gasLimit: 50000n,
            chainID: config.chainID,
        });

        assert.throws(() => {
            factory.createRelayedV2Transaction({
                innerTransaction: innerTransaction,
                innerTransactionGasLimit: 50000n,
                relayerAddress: carol.address,
            }),
                "The gas limit should not be set for the inner transaction";
        });

        innerTransaction.gasLimit = 0n;

        assert.throws(() => {
            factory.createRelayedV2Transaction({
                innerTransaction: innerTransaction,
                innerTransactionGasLimit: 50000n,
                relayerAddress: carol.address,
            }),
                "The inner transaction is not signed";
        });
    });

    it("should create relayed v2 transaction", async function () {
        let innerTransaction = new Transaction({
            sender: bob.address.bech32(),
            receiver: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            gasLimit: 0n,
            chainID: config.chainID,
            data: Buffer.from("getContractConfig"),
            nonce: 15n,
            version: 2,
            options: 0,
        });

        const serializedInnerTransaction = transactionComputer.computeBytesForSigning(innerTransaction);
        innerTransaction.signature = await bob.signer.sign(serializedInnerTransaction);

        const relayedTransaction = factory.createRelayedV2Transaction({
            innerTransaction: innerTransaction,
            innerTransactionGasLimit: 60000000n,
            relayerAddress: alice.address,
        });
        relayedTransaction.nonce = 37n;

        const serializedRelayedTransaction = transactionComputer.computeBytesForSigning(relayedTransaction);
        relayedTransaction.signature = await alice.signer.sign(serializedRelayedTransaction);

        assert.equal(relayedTransaction.version, 2);
        assert.equal(relayedTransaction.options, 0);
        assert.equal(relayedTransaction.gasLimit.toString(), "60414500");
        assert.equal(
            Buffer.from(relayedTransaction.data).toString(),
            "relayedTxV2@000000000000000000010000000000000000000000000000000000000002ffff@0f@676574436f6e7472616374436f6e666967@9b5f2023b8423891f994f7c2fe1560ef9a1370e13243acabe3a457320416493323ba1f5e7e1dab9932ec8bab18b60745c3a283f737fc42aa06b12db92200eb00",
        );
    });

    it("should create relayed v3 transaction", async function () {
        let innerTransaction = new Transaction({
            sender: bob.address.toBech32(),
            receiver: bob.address.toBech32(),
            gasLimit: 50000n,
            chainID: config.chainID,
            nonce: 0n,
            version: 2,
            relayer: alice.address.toBech32(),
        });

        const serializedInnerTransaction = transactionComputer.computeBytesForSigning(innerTransaction);
        innerTransaction.signature = await bob.signer.sign(serializedInnerTransaction);

        const relayedTransaction = factory.createRelayedV3Transaction({
            relayerAddress: alice.address,
            innerTransactions: [innerTransaction],
        });

        const serializedRelayedTransaction = transactionComputer.computeBytesForSigning(relayedTransaction);
        relayedTransaction.signature = await alice.signer.sign(serializedRelayedTransaction);

        assert.equal(
            Buffer.from(relayedTransaction.signature).toString("hex"),
            "6347b4276985947e4036c76edac2bf3225359b677d98cd3df99c5a8fa0ec1bcd4964a70c97a1023d360fc73db9d0922757b4f9288dc2575d93439de0940f5700",
        );
        assert.equal(relayedTransaction.gasLimit, 100000n);
    });

    it("should fail to create relayed v3 transaction", async function () {
        assert.throws(() => {
            factory.createRelayedV3Transaction({
                relayerAddress: alice.address,
                innerTransactions: [],
            });
        }, "No inner transctions provided");

        const innerTransaction = new Transaction({
            sender: bob.address.toBech32(),
            receiver: bob.address.toBech32(),
            gasLimit: 50000n,
            chainID: config.chainID,
            nonce: 0n,
            version: 2,
            relayer: carol.address.toBech32(),
        });

        assert.throws(() => {
            factory.createRelayedV3Transaction({
                relayerAddress: alice.address,
                innerTransactions: [innerTransaction],
            });
        }, "Inner transaction is not signed");

        const serializedInnerTransaction = transactionComputer.computeBytesForSigning(innerTransaction);
        innerTransaction.signature = await bob.signer.sign(serializedInnerTransaction);

        assert.throws(() => {
            factory.createRelayedV3Transaction({
                relayerAddress: alice.address,
                innerTransactions: [innerTransaction],
            });
        }, "The inner transaction has an incorrect relayer address");
    });
});
