import { assert } from "chai";
import { Address } from "./address";
import { TokenTransfer } from "./tokens";
import {
    DCDTNFTTransferPayloadBuilder,
    DCDTTransferPayloadBuilder,
    MultiDCDTNFTTransferPayloadBuilder,
} from "./tokenTransferBuilders";

describe("test token transfer builders", () => {
    it("should work with DCDT transfers", () => {
        const transfer = TokenTransfer.fungibleFromAmount("COUNTER-8b028f", "100.00", 0);
        const payload = new DCDTTransferPayloadBuilder().setPayment(transfer).build();
        assert.equal(payload.toString(), "DCDTTransfer@434f554e5445522d386230323866@64");
    });

    it("should work with DCDTNFT transfers (NFT)", () => {
        const transfer = TokenTransfer.nonFungible("MOAJS-38f249", 1);
        const payload = new DCDTNFTTransferPayloadBuilder()
            .setPayment(transfer)
            .setDestination(new Address("moa1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruq0yu4wk"))
            .build();

        assert.equal(
            payload.toString(),
            "DCDTNFTTransfer@4d4f414a532d333866323439@01@01@8049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f8",
        );
    });

    it("should work with DCDTNFT transfers (SFT)", () => {
        const transfer = TokenTransfer.semiFungible("SEMI-9efd0f", 1, 5);

        const payload = new DCDTNFTTransferPayloadBuilder()
            .setPayment(transfer)
            .setDestination(new Address("moa1testnlersh4z0wsv8kjx39me4rmnvjkwu8dsaea7ukdvvc9z396qfw237w"))
            .build();

        assert.equal(
            payload.toString(),
            "DCDTNFTTransfer@53454d492d396566643066@01@05@5e60b9ff2385ea27ba0c3da4689779a8f7364acee1db0ee7bee59ac660a28974",
        );
    });

    it("should work with Multi DCDTNFT transfers", () => {
        const transferOne = TokenTransfer.nonFungible("MOAJS-38f249", 1);
        const transferTwo = TokenTransfer.fungibleFromAmount("BAR-c80d29", "10.00", 18);
        const payload = new MultiDCDTNFTTransferPayloadBuilder()
            .setPayments([transferOne, transferTwo])
            .setDestination(new Address("moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8"))
            .build();

        assert.equal(
            payload.toString(),
            "MultiDCDTNFTTransfer@0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1@02@4d4f414a532d333866323439@01@01@4241522d633830643239@@8ac7230489e80000",
        );
    });
});
