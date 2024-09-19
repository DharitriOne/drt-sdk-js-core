import { assert } from "chai";
import { Address } from "./address";
import { GasEstimator } from "./gasEstimator";
import { TokenTransfer } from "./tokens";
import { TransactionPayload } from "./transactionPayload";
import { TransferTransactionsFactory } from "./transactionsFactories/transferTransactionsFactory";

describe("test transaction factory", () => {
    const factory = new TransferTransactionsFactory(new GasEstimator());

    it("should create REWA transfers", () => {
        const transactionWithData = factory.createREWATransfer({
            value: TokenTransfer.rewaFromAmount(10.5),
            sender: Address.fromBech32("moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8"),
            receiver: new Address("moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td"),
            data: new TransactionPayload("hello"),
            chainID: "D",
        });

        assert.equal(
            transactionWithData.getSender().bech32(),
            "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
        );
        assert.equal(
            transactionWithData.getReceiver().bech32(),
            "moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td",
        );
        assert.equal(transactionWithData.getValue(), "10500000000000000000");
        assert.equal(transactionWithData.getGasLimit(), 50000 + 5 * 1500);
        assert.equal(transactionWithData.getData().toString(), "hello");
        assert.equal(transactionWithData.getChainID(), "D");

        const transactionWithoutData = factory.createREWATransfer({
            value: TokenTransfer.rewaFromAmount(10.5),
            sender: Address.fromBech32("moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8"),
            receiver: new Address("moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td"),
            chainID: "D",
        });

        assert.equal(
            transactionWithoutData.getSender().bech32(),
            "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
        );
        assert.equal(
            transactionWithoutData.getReceiver().bech32(),
            "moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td",
        );
        assert.equal(transactionWithoutData.getValue(), "10500000000000000000");
        assert.equal(transactionWithoutData.getGasLimit(), 50000);
        assert.equal(transactionWithoutData.getData().toString(), "");
        assert.equal(transactionWithoutData.getChainID(), "D");
    });

    it("should create DCDT transfers", () => {
        const transaction = factory.createDCDTTransfer({
            tokenTransfer: TokenTransfer.fungibleFromAmount("TEST-8b028f", "100.00", 2),
            sender: Address.fromBech32("moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8"),
            receiver: Address.fromBech32("moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td"),
            chainID: "D",
        });

        assert.equal(
            transaction.getSender().bech32(),
            "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
        );
        assert.equal(
            transaction.getReceiver().bech32(),
            "moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td",
        );
        assert.equal(transaction.getValue(), "");
        assert.equal(transaction.getGasLimit(), 50000 + 40 * 1500 + 200000 + 100000);
        assert.equal(transaction.getData().toString(), "DCDTTransfer@544553542d386230323866@2710");
        assert.equal(transaction.getChainID(), "D");
    });

    it("should create DCDTNFT transfers", () => {
        const transaction = factory.createDCDTNFTTransfer({
            tokenTransfer: TokenTransfer.nonFungible("TEST-38f249", 1),
            destination: new Address("moa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruq0yu4wk"),
            sender: new Address("moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td"),
            chainID: "D",
        });

        assert.equal(
            transaction.getSender().bech32(),
            "moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td",
        );
        assert.equal(
            transaction.getReceiver().bech32(),
            "moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td",
        );
        assert.equal(transaction.getValue(), "");
        assert.equal(transaction.getGasLimit(), 50000 + 109 * 1500 + 200000 + 800000);
        assert.equal(
            transaction.getData().toString(),
            "DCDTNFTTransfer@544553542d333866323439@01@01@8049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f8",
        );
        assert.equal(transaction.getChainID(), "D");
    });

    it("should create Multi DCDTNFT transfers", () => {
        const transaction = factory.createMultiDCDTNFTTransfer({
            tokenTransfers: [
                TokenTransfer.nonFungible("FOO-38f249", 1),
                TokenTransfer.fungibleFromAmount("BAR-c80d29", "10.00", 18),
            ],
            destination: new Address("moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8"),
            sender: new Address("moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td"),
            chainID: "D",
        });

        assert.equal(
            transaction.getSender().bech32(),
            "moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td",
        );
        assert.equal(
            transaction.getReceiver().bech32(),
            "moa1dc3yzxxeq69wvf583gw0h67td226gu2ahpk3k50qdgzzym8npltqntt8td",
        );
        assert.equal(transaction.getValue(), "");
        assert.equal(transaction.getGasLimit(), 50000 + 154 * 1500 + (200000 + 800000) * 2);
        assert.equal(
            transaction.getData().toString(),
            "MultiDCDTNFTTransfer@0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1@02@464f4f2d333866323439@01@01@4241522d633830643239@@8ac7230489e80000",
        );
        assert.equal(transaction.getChainID(), "D");
    });
});
