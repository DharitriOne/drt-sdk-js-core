import { assert } from "chai";
import { GasEstimator } from "./gasEstimator";

describe("test gas estimator", () => {
    it("should estimate gas limit (default gas configuration)", () => {
        const estimator = new GasEstimator();

        assert.equal(estimator.forREWATransfer(0), 50000);
        assert.equal(estimator.forREWATransfer(3), 50000 + 3 * 1500);

        assert.equal(estimator.forDCDTTransfer(80), 50000 + 80 * 1500 + 200000 + 100000);
        assert.equal(estimator.forDCDTTransfer(100), 50000 + 100 * 1500 + 200000 + 100000);

        assert.equal(estimator.forDCDTNFTTransfer(80), 50000 + 80 * 1500 + 200000 + 800000);
        assert.equal(estimator.forDCDTNFTTransfer(100), 50000 + 100 * 1500 + 200000 + 800000);

        assert.equal(estimator.forMultiDCDTNFTTransfer(80, 1), 50000 + 80 * 1500 + (200000 + 800000) * 1);
        assert.equal(estimator.forMultiDCDTNFTTransfer(80, 3), 50000 + 80 * 1500 + (200000 + 800000) * 3);
    });

    it("should estimate gas limit (custom gas configuration)", () => {
        const estimator = new GasEstimator({
            minGasLimit: 10000,
            gasPerDataByte: 3000,
            gasCostDCDTTransfer: 200000,
            gasCostDCDTNFTTransfer: 300000,
            gasCostDCDTNFTMultiTransfer: 400000,
        });

        assert.equal(estimator.forREWATransfer(0), 10000);
        assert.equal(estimator.forREWATransfer(3), 10000 + 3 * 3000);

        assert.equal(estimator.forDCDTTransfer(80), 10000 + 80 * 3000 + 200000 + 100000);
        assert.equal(estimator.forDCDTTransfer(100), 10000 + 100 * 3000 + 200000 + 100000);

        assert.equal(estimator.forDCDTNFTTransfer(80), 10000 + 80 * 3000 + 300000 + 800000);
        assert.equal(estimator.forDCDTNFTTransfer(100), 10000 + 100 * 3000 + 300000 + 800000);

        assert.equal(estimator.forMultiDCDTNFTTransfer(80, 1), 10000 + 80 * 3000 + (400000 + 800000) * 1);
        assert.equal(estimator.forMultiDCDTNFTTransfer(80, 3), 10000 + 80 * 3000 + (400000 + 800000) * 3);
    });
});
