import { Err, ErrBadUsage } from "../errors";
import {
    IAddress,
    IChainID,
    IGasLimit,
    IGasPrice,
    INonce,
    ITokenTransfer,
    ITransactionPayload,
    ITransactionValue,
} from "../interface";
import {
    AddressValue,
    ArgSerializer,
    BigUIntValue,
    BytesValue,
    TypedValue,
    U16Value,
    U64Value,
} from "../smartcontracts";
import { TokenComputer, TokenTransfer } from "../tokens";
import { Transaction } from "../transaction";
import { TransactionPayload } from "../transactionPayload";
import { TokenTransfersDataBuilder } from "./tokenTransfersDataBuilder";
import { TransactionBuilder } from "./transactionBuilder";

const ADDITIONAL_GAS_FOR_DCDT_TRANSFER = 100000;
const ADDITIONAL_GAS_FOR_DCDT_NFT_TRANSFER = 800000;

interface IConfig {
    chainID: string;
    minGasLimit: bigint;
    gasLimitPerByte: bigint;
    gasLimitDCDTTransfer: bigint;
    gasLimitDCDTNFTTransfer: bigint;
    gasLimitMultiDCDTNFTTransfer: bigint;
}

interface IGasEstimator {
    forREWATransfer(dataLength: number): number;
    forDCDTTransfer(dataLength: number): number;
    forDCDTNFTTransfer(dataLength: number): number;
    forMultiDCDTNFTTransfer(dataLength: number, numTransfers: number): number;
}

/**
 * Use this class to create transactions for native token transfers (REWA) or custom tokens transfers (DCDT/NTF/MetaDCDT).
 */
export class TransferTransactionsFactory {
    private readonly config?: IConfig;
    private readonly tokenTransfersDataBuilder?: TokenTransfersDataBuilder;
    private readonly tokenComputer?: TokenComputer;
    private readonly gasEstimator?: IGasEstimator;

    /**
     * Should be instantiated using `Config`.
     * Instantiating this class using GasEstimator represents the legacy version of this class.
     * The legacy version contains methods like `createREWATransfer`, `createDCDTTransfer`, `createDCDTNFTTransfer` and `createMultiDCDTNFTTransfer`.
     * This was done in order to minimize breaking changes in client code.
     */
    constructor(options: IGasEstimator | { config: IConfig }) {
        if (this.isGasEstimator(options)) {
            this.gasEstimator = options;
        } else {
            this.config = options.config;
            this.tokenComputer = new TokenComputer();
            this.tokenTransfersDataBuilder = new TokenTransfersDataBuilder();
        }
    }

    private isGasEstimator(options: any): options is IGasEstimator {
        return (
            typeof options === "object" &&
            typeof options.forREWATransfer === "function" &&
            typeof options.forDCDTTransfer === "function" &&
            typeof options.forDCDTNFTTransfer === "function" &&
            typeof options.forMultiDCDTNFTTransfer === "function"
        );
    }

    private isGasEstimatorDefined(): boolean {
        return this.gasEstimator !== undefined;
    }

    private ensureConfigIsDefined() {
        if (this.config === undefined) {
            throw new Err("'config' is not defined");
        }
    }

    createTransactionForNativeTokenTransfer(options: {
        sender: IAddress;
        receiver: IAddress;
        nativeAmount: bigint;
        data?: Uint8Array;
    }): Transaction {
        this.ensureConfigIsDefined();

        const data = options.data || new Uint8Array();

        return new Transaction({
            sender: options.sender.bech32(),
            receiver: options.receiver.bech32(),
            chainID: this.config!.chainID,
            gasLimit: this.computeGasForMoveBalance(this.config!, data),
            data: data,
            value: options.nativeAmount,
        });
    }

    createTransactionForDCDTTokenTransfer(options: {
        sender: IAddress;
        receiver: IAddress;
        tokenTransfers: TokenTransfer[];
    }): Transaction {
        this.ensureConfigIsDefined();

        const numberOfTransfers = options.tokenTransfers.length;

        if (numberOfTransfers === 0) {
            throw new ErrBadUsage("No token transfer has been provided");
        }

        if (numberOfTransfers === 1) {
            return this.createSingleDCDTTransferTransaction(options);
        }

        const dataParts = this.tokenTransfersDataBuilder!.buildDataPartsForMultiDCDTNFTTransfer(
            options.receiver,
            options.tokenTransfers,
        );

        const extraGasForTransfer =
            this.config!.gasLimitMultiDCDTNFTTransfer * BigInt(numberOfTransfers) +
            BigInt(ADDITIONAL_GAS_FOR_DCDT_NFT_TRANSFER);

        return new TransactionBuilder({
            config: this.config!,
            sender: options.sender,
            receiver: options.sender,
            dataParts: dataParts,
            gasLimit: extraGasForTransfer,
            addDataMovementGas: true,
        }).build();
    }

    createTransactionForTransfer(options: {
        sender: IAddress;
        receiver: IAddress;
        nativeAmount?: bigint;
        tokenTransfers?: TokenTransfer[];
        data?: Uint8Array;
    }): Transaction {
        const nativeAmount = options.nativeAmount ?? 0n;
        let tokenTransfers = options.tokenTransfers ? [...options.tokenTransfers] : [];
        const numberOfTokens = tokenTransfers.length;

        if (numberOfTokens && options.data?.length) {
            throw new ErrBadUsage("Can't set data field when sending dcdt tokens");
        }

        if ((nativeAmount && numberOfTokens === 0) || options.data) {
            return this.createTransactionForNativeTokenTransfer({
                sender: options.sender,
                receiver: options.receiver,
                nativeAmount: nativeAmount,
                data: options.data,
            });
        }

        const nativeTransfer = nativeAmount ? TokenTransfer.newFromRewaAmount(nativeAmount) : undefined;
        if (nativeTransfer) {
            tokenTransfers.push(nativeTransfer);
        }

        return this.createTransactionForDCDTTokenTransfer({
            sender: options.sender,
            receiver: options.receiver,
            tokenTransfers: tokenTransfers,
        });
    }

    /**
     * This is a legacy method. Can only be used if the class was instantiated using `GasEstimator`.
     * Use {@link createTransactionForNativeTokenTransfer} instead.
     */
    createREWATransfer(args: {
        nonce?: INonce;
        value: ITransactionValue;
        receiver: IAddress;
        sender: IAddress;
        gasPrice?: IGasPrice;
        gasLimit?: IGasLimit;
        data?: ITransactionPayload;
        chainID: IChainID;
    }) {
        if (!this.isGasEstimatorDefined()) {
            throw new Err(
                "You are calling a legacy function to create an REWA transfer transaction. If this is your intent, then instantiate the class using a `GasEstimator`. Or, instead, use the new, recommended `createTransactionForNativeTokenTransfer` method.",
            );
        }

        const dataLength = args.data?.length() || 0;
        const estimatedGasLimit = this.gasEstimator!.forREWATransfer(dataLength);

        return new Transaction({
            nonce: args.nonce,
            value: args.value,
            receiver: args.receiver,
            sender: args.sender,
            gasPrice: args.gasPrice,
            gasLimit: args.gasLimit || estimatedGasLimit,
            data: args.data,
            chainID: args.chainID,
        });
    }

    /**
     * This is a legacy method. Can only be used if the class was instantiated using `GasEstimator`.
     * Use {@link createTransactionForDCDTTokenTransfer} instead.
     */
    createDCDTTransfer(args: {
        tokenTransfer: ITokenTransfer;
        nonce?: INonce;
        receiver: IAddress;
        sender: IAddress;
        gasPrice?: IGasPrice;
        gasLimit?: IGasLimit;
        chainID: IChainID;
    }) {
        if (!this.isGasEstimatorDefined()) {
            throw new Err(
                "You are calling a legacy function to create an DCDT transfer transaction. If this is your intent, then instantiate the class using a `GasEstimator`. Or, instead, use the new, recommended `createTransactionForDCDTTokenTransfer` method.",
            );
        }

        const { argumentsString } = new ArgSerializer().valuesToString([
            // The token identifier
            BytesValue.fromUTF8(args.tokenTransfer.tokenIdentifier),
            // The transfered amount
            new BigUIntValue(args.tokenTransfer.valueOf()),
        ]);

        const data = `DCDTTransfer@${argumentsString}`;
        const transactionPayload = new TransactionPayload(data);
        const dataLength = transactionPayload.length() || 0;
        const estimatedGasLimit = this.gasEstimator!.forDCDTTransfer(dataLength);

        return new Transaction({
            nonce: args.nonce,
            receiver: args.receiver,
            sender: args.sender,
            gasPrice: args.gasPrice,
            gasLimit: args.gasLimit || estimatedGasLimit,
            data: transactionPayload,
            chainID: args.chainID,
        });
    }

    /**
     * This is a legacy method. Can only be used if the class was instantiated using `GasEstimator`.
     * Use {@link createTransactionForDCDTTokenTransfer} instead.
     */
    createDCDTNFTTransfer(args: {
        tokenTransfer: ITokenTransfer;
        nonce?: INonce;
        destination: IAddress;
        sender: IAddress;
        gasPrice?: IGasPrice;
        gasLimit?: IGasLimit;
        chainID: IChainID;
    }) {
        if (!this.isGasEstimatorDefined()) {
            throw new Err(
                "You are calling a legacy function to create an DCDTNFT transfer transaction. If this is your intent, then instantiate the class using a `GasEstimator`. Or, instead, use the new, recommended `createTransactionForDCDTTokenTransfer` method.",
            );
        }

        const { argumentsString } = new ArgSerializer().valuesToString([
            // The token identifier
            BytesValue.fromUTF8(args.tokenTransfer.tokenIdentifier),
            // The nonce of the token
            new U64Value(args.tokenTransfer.nonce),
            // The transferred quantity
            new BigUIntValue(args.tokenTransfer.valueOf()),
            // The destination address
            new AddressValue(args.destination),
        ]);

        const data = `DCDTNFTTransfer@${argumentsString}`;
        const transactionPayload = new TransactionPayload(data);
        const dataLength = transactionPayload.length() || 0;
        const estimatedGasLimit = this.gasEstimator!.forDCDTNFTTransfer(dataLength);

        return new Transaction({
            nonce: args.nonce,
            receiver: args.sender,
            sender: args.sender,
            gasPrice: args.gasPrice,
            gasLimit: args.gasLimit || estimatedGasLimit,
            data: transactionPayload,
            chainID: args.chainID,
        });
    }

    /**
     * This is a legacy method. Can only be used if the class was instantiated using `GasEstimator`.
     * Use {@link createTransactionForDCDTTokenTransfer} instead.
     */
    createMultiDCDTNFTTransfer(args: {
        tokenTransfers: ITokenTransfer[];
        nonce?: INonce;
        destination: IAddress;
        sender: IAddress;
        gasPrice?: IGasPrice;
        gasLimit?: IGasLimit;
        chainID: IChainID;
    }) {
        if (!this.isGasEstimatorDefined()) {
            throw new Err(
                "You are calling a legacy function to create a MultiDCDTNFT transfer transaction. If this is your intent, then instantiate the class using a `GasEstimator`. Or, instead, use the new, recommended `createTransactionForDCDTTokenTransfer` method.",
            );
        }

        const parts: TypedValue[] = [
            // The destination address
            new AddressValue(args.destination),
            // Number of tokens
            new U16Value(args.tokenTransfers.length),
        ];

        for (const payment of args.tokenTransfers) {
            parts.push(
                ...[
                    // The token identifier
                    BytesValue.fromUTF8(payment.tokenIdentifier),
                    // The nonce of the token
                    new U64Value(payment.nonce),
                    // The transfered quantity
                    new BigUIntValue(payment.valueOf()),
                ],
            );
        }

        const { argumentsString } = new ArgSerializer().valuesToString(parts);
        const data = `MultiDCDTNFTTransfer@${argumentsString}`;
        const transactionPayload = new TransactionPayload(data);
        const dataLength = transactionPayload.length() || 0;
        const estimatedGasLimit = this.gasEstimator!.forMultiDCDTNFTTransfer(dataLength, args.tokenTransfers.length);

        return new Transaction({
            nonce: args.nonce,
            receiver: args.sender,
            sender: args.sender,
            gasPrice: args.gasPrice,
            gasLimit: args.gasLimit || estimatedGasLimit,
            data: transactionPayload,
            chainID: args.chainID,
        });
    }

    private createSingleDCDTTransferTransaction(options: {
        sender: IAddress;
        receiver: IAddress;
        tokenTransfers: TokenTransfer[];
    }): Transaction {
        this.ensureConfigIsDefined();

        let dataParts: string[] = [];
        const transfer = options.tokenTransfers[0];
        let extraGasForTransfer = 0n;
        let receiver = options.receiver;

        if (this.tokenComputer!.isFungible(transfer.token)) {
            dataParts = this.tokenTransfersDataBuilder!.buildDataPartsForDCDTTransfer(transfer);
            extraGasForTransfer = this.config!.gasLimitDCDTTransfer + BigInt(ADDITIONAL_GAS_FOR_DCDT_TRANSFER);
        } else {
            dataParts = this.tokenTransfersDataBuilder!.buildDataPartsForSingleDCDTNFTTransfer(transfer, receiver);
            extraGasForTransfer = this.config!.gasLimitDCDTNFTTransfer + BigInt(ADDITIONAL_GAS_FOR_DCDT_NFT_TRANSFER);
            receiver = options.sender;
        }

        return new TransactionBuilder({
            config: this.config!,
            sender: options.sender,
            receiver: receiver,
            dataParts: dataParts,
            gasLimit: extraGasForTransfer,
            addDataMovementGas: true,
        }).build();
    }

    private computeGasForMoveBalance(config: IConfig, data: Uint8Array): bigint {
        return config.minGasLimit + config.gasLimitPerByte * BigInt(data.length);
    }
}
