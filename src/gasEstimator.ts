interface IGasConfiguration {
    readonly minGasLimit: number;
    readonly gasPerDataByte: number;
    readonly gasCostDCDTTransfer: number;
    readonly gasCostDCDTNFTTransfer: number;
    readonly gasCostDCDTNFTMultiTransfer: number;
}

/**
 * This is mirroring (on a best efforts basis) the network's gas configuration & gas schedule:
 *  - https://gateway.dharitri.com/network/config
 *  - https://github.com/DharitriOne/drt-chain-mainnet-config/tree/master/gasSchedules
 *  - https://github.com/DharitriOne/drt-chain-mainnet-config/blob/master/enableEpochs.toml#L200
 */
export const DefaultGasConfiguration: IGasConfiguration = {
    minGasLimit: 50000,
    gasPerDataByte: 1500,
    gasCostDCDTTransfer: 200000,
    gasCostDCDTNFTTransfer: 200000,
    gasCostDCDTNFTMultiTransfer: 200000,
};

// Additional gas to account for eventual increases in gas requirements (thus avoid fast-breaking changes in clients of the library).
const ADDITIONAL_GAS_FOR_DCDT_TRANSFER = 100000;

// Additional gas to account for extra blockchain operations (e.g. data movement (between accounts) for NFTs),
// and for eventual increases in gas requirements (thus avoid fast-breaking changes in clients of the library).
const ADDITIONAL_GAS_FOR_DCDT_NFT_TRANSFER = 800000;

/**
 * @deprecated This will be remove with the next release as the only place where it is used is a deprecated constructor.
 */
export class GasEstimator {
    private readonly gasConfiguration: IGasConfiguration;

    constructor(gasConfiguration?: IGasConfiguration) {
        this.gasConfiguration = gasConfiguration || DefaultGasConfiguration;
    }

    forREWATransfer(dataLength: number) {
        const gasLimit = this.gasConfiguration.minGasLimit + this.gasConfiguration.gasPerDataByte * dataLength;

        return gasLimit;
    }

    forDCDTTransfer(dataLength: number) {
        const gasLimit =
            this.gasConfiguration.minGasLimit +
            this.gasConfiguration.gasCostDCDTTransfer +
            this.gasConfiguration.gasPerDataByte * dataLength +
            ADDITIONAL_GAS_FOR_DCDT_TRANSFER;

        return gasLimit;
    }

    forDCDTNFTTransfer(dataLength: number) {
        const gasLimit =
            this.gasConfiguration.minGasLimit +
            this.gasConfiguration.gasCostDCDTNFTTransfer +
            this.gasConfiguration.gasPerDataByte * dataLength +
            ADDITIONAL_GAS_FOR_DCDT_NFT_TRANSFER;

        return gasLimit;
    }

    forMultiDCDTNFTTransfer(dataLength: number, numTransfers: number) {
        const gasLimit =
            this.gasConfiguration.minGasLimit +
            (this.gasConfiguration.gasCostDCDTNFTMultiTransfer + ADDITIONAL_GAS_FOR_DCDT_NFT_TRANSFER) * numTransfers +
            this.gasConfiguration.gasPerDataByte * dataLength;

        return gasLimit;
    }
}
