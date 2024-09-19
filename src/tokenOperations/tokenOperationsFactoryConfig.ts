import BigNumber from "bignumber.js";
import { Address } from "../address";
import { IAddress, IChainID, IGasLimit, IGasPrice } from "../interface";

/**
 * @deprecated Use {@link TransactionsFactoryConfig} instead.
 */
export class TokenOperationsFactoryConfig {
    chainID: IChainID;
    minGasPrice: IGasPrice = 1000000000;
    minGasLimit = 50000;
    gasLimitPerByte = 1500;
    gasLimitIssue: IGasLimit = 60000000;
    gasLimitToggleBurnRoleGlobally: IGasLimit = 60000000;
    gasLimitDCDTLocalMint: IGasLimit = 300000;
    gasLimitDCDTLocalBurn: IGasLimit = 300000;
    gasLimitSetSpecialRole: IGasLimit = 60000000;
    gasLimitPausing: IGasLimit = 60000000;
    gasLimitFreezing: IGasLimit = 60000000;
    gasLimitWiping: IGasLimit = 60000000;
    gasLimitDCDTNFTCreate: IGasLimit = 3000000;
    gasLimitDCDTNFTUpdateAttributes: IGasLimit = 1000000;
    gasLimitDCDTNFTAddQuantity: IGasLimit = 1000000;
    gasLimitDCDTNFTBurn: IGasLimit = 1000000;
    gasLimitStorePerByte: IGasLimit = 50000;
    issueCost: BigNumber.Value = "50000000000000000";
    dcdtContractAddress: IAddress = Address.fromBech32(
        "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
    );

    constructor(chainID: IChainID) {
        this.chainID = chainID;
    }
}
