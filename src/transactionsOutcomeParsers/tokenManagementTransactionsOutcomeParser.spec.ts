import { assert } from "chai";
import { ErrParseTransactionOutcome } from "../errors";
import { b64TopicsToBytes } from "../testutils";
import { SmartContractResult, TransactionEvent, TransactionLogs, TransactionOutcome } from "./resources";
import { TokenManagementTransactionsOutcomeParser } from "./tokenManagementTransactionsOutcomeParser";

describe("test token management transactions outcome parser", () => {
    const parser = new TokenManagementTransactionsOutcomeParser();

    it("should test ensure error", () => {
        const encodedTopics = ["Avk0jZ1kR+l9c76wQQoYcu4hvXPz+jxxTdqQeaCrbX8=", "dGlja2VyIG5hbWUgaXMgbm90IHZhbGlk"];
        const event = new TransactionEvent({
            address: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            identifier: "signalError",
            topics: b64TopicsToBytes(encodedTopics),
            dataItems: [Buffer.from("QDc1NzM2NTcyMjA2NTcyNzI2Zjcy", "base64")],
        });

        const logs = new TransactionLogs({ events: [event] });
        const txOutcome = new TransactionOutcome({ logs: logs });

        assert.throws(
            () => {
                parser.parseIssueFungible(txOutcome);
            },
            ErrParseTransactionOutcome,
            "encountered signalError: ticker name is not valid (user error)",
        );
    });

    it("should test parse issue fungible", () => {
        const identifier = "ZZZ-9ee87d";
        const base64Identifier = Buffer.from(identifier).toString("base64");

        const encodedTopics = [base64Identifier, "U0VDT05E", "Wlpa", "RnVuZ2libGVEQ0RU", "Ag=="];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "issue",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const logs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({ logs: logs });

        const outcome = parser.parseIssueFungible(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].tokenIdentifier, identifier);
    });

    it("should test parse issue non fungible", () => {
        const identifier = "NFT-f01d1e";
        const base64Identifier = Buffer.from(identifier).toString("base64");

        let encodedTopics = [
            "TkZULWYwMWQxZQ==",
            "",
            "Y2FuVXBncmFkZQ==",
            "dHJ1ZQ==",
            "Y2FuQWRkU3BlY2lhbFJvbGVz",
            "dHJ1ZQ==",
        ];
        const firstEvent = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "upgradeProperties",
            topics: b64TopicsToBytes(encodedTopics),
        });

        encodedTopics = ["TkZULWYwMWQxZQ==", "", "", "RVNEVFJvbGVCdXJuRm9yQWxs"];
        const secondEvent = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTSetBurnRoleForAll",
            topics: b64TopicsToBytes(encodedTopics),
        });

        encodedTopics = [base64Identifier, "TkZURVNU", "TkZU", "Tm9uRnVuZ2libGVEQ0RU"];
        const thirdEvent = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "issueNonFungible",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const logs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [firstEvent, secondEvent, thirdEvent],
        });

        const txOutcome = new TransactionOutcome({ logs: logs });

        const outcome = parser.parseIssueNonFungible(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].tokenIdentifier, identifier);
    });

    it("should test parse issue semi fungible", () => {
        const identifier = "SEMIFNG-2c6d9f";
        const base64Identifier = Buffer.from(identifier).toString("base64");

        const encodedTopics = [base64Identifier, "U0VNSQ==", "U0VNSUZORw==", "U2VtaUZ1bmdpYmxlRVNEVA=="];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "issueSemiFungible",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const logs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({ logs: logs });

        const outcome = parser.parseIssueSemiFungible(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].tokenIdentifier, identifier);
    });

    it("should test parse register meta dcdt", () => {
        const identifier = "METATEST-e05d11";
        const base64Identifier = Buffer.from(identifier).toString("base64");

        const encodedTopics = [base64Identifier, "TUVURVNU", "TUVUQVRFU1Q=", "TWV0YUVTRFQ="];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "registerMetaDCDT",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const logs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({ logs: logs });

        const outcome = parser.parseRegisterMetaDcdt(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].tokenIdentifier, identifier);
    });

    it("should test parse register and set all roles", () => {
        const firstIdentifier = "LMAO-d9f892";
        const firstBase64Identifier = Buffer.from(firstIdentifier).toString("base64");

        const secondIdentifier = "TST-123456";
        const secondBase64Identifier = Buffer.from(secondIdentifier).toString("base64");

        const roles = ["DCDTRoleLocalMint", "DCDTRoleLocalBurn"];

        let encodedTopics = [firstBase64Identifier, "TE1BTw==", "TE1BTw==", "RnVuZ2libGVEQ0RU", "Ag=="];
        const firstEvent = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "registerAndSetAllRoles",
            topics: b64TopicsToBytes(encodedTopics),
        });

        encodedTopics = [secondBase64Identifier, "TE1BTw==", "TE1BTw==", "RnVuZ2libGVEQ0RU", "Ag=="];
        const secondEvent = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "registerAndSetAllRoles",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [firstEvent, secondEvent],
        });

        encodedTopics = ["TE1BTy1kOWY4OTI=", "", "", "RENEVFJvbGVMb2NhbE1pbnQ=", "RENEVFJvbGVMb2NhbEJ1cm4="];
        const firstResultEvent = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTSetRole",
            topics: b64TopicsToBytes(encodedTopics),
        });

        encodedTopics = ["VFNULTEyMzQ1Ng==", "", "", "RENEVFJvbGVMb2NhbE1pbnQ=", "RENEVFJvbGVMb2NhbEJ1cm4="];
        const secondResultEvent = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTSetRole",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const resultLogs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [firstResultEvent, secondResultEvent],
        });

        const scResult = new SmartContractResult({
            sender: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            receiver: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            data: Buffer.from(
                "RENEVFNldFJvbGVANGM0ZDQxNGYyZDY0Mzk2NjM4MzkzMkA0NTUzNDQ1NDUyNmY2YzY1NGM2ZjYzNjE2YzRkNjk2ZTc0QDQ1NTM0NDU0NTI2ZjZjNjU0YzZmNjM2MTZjNDI3NTcyNmU=",
                "base64",
            ),
            logs: resultLogs,
        });

        const txOutcome = new TransactionOutcome({
            smartContractResults: [scResult],
            logs: transactionLogs,
        });

        const outcome = parser.parseRegisterAndSetAllRoles(txOutcome);
        assert.lengthOf(outcome, 2);

        assert.equal(outcome[0].tokenIdentifier, firstIdentifier);
        assert.deepEqual(outcome[0].roles, roles);

        assert.equal(outcome[1].tokenIdentifier, secondIdentifier);
        assert.deepEqual(outcome[1].roles, roles);
    });

    it("should test parse register set special role", () => {
        const identifier = "METATEST-e05d11";
        const base64Identifier = Buffer.from(identifier).toString("base64");
        const roles = ["DCDTRoleNFTCreate", "DCDTRoleNFTAddQuantity", "DCDTRoleNFTBurn"];

        const encodedTopics = [
            base64Identifier,
            "",
            "",
            "RENEVFJvbGVORlRDcmVhdGU=",
            "RENEVFJvbGVORlRBZGRRdWFudGl0eQ==",
            "RENEVFJvbGVORlRCdXJu",
        ];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTSetRole",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({
            logs: transactionLogs,
        });

        const outcome = parser.parseSetSpecialRole(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].userAddress, "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6");
        assert.equal(outcome[0].tokenIdentifier, identifier);
        assert.deepEqual(outcome[0].roles, roles);
    });

    it("should test parse nft create", () => {
        const identifier = "NFT-f01d1e";
        const base64Identifier = Buffer.from(identifier).toString("base64");
        const nonce = BigInt(1);
        const initialQuantity = BigInt(1);

        const encodedTopics = [
            base64Identifier,
            "AQ==",
            "AQ==",
            "CAESAgABIuUBCAESCE5GVEZJUlNUGiA8NdfqyxqZpKDMqlN+8MwK4Qn0H2wrQCID5jO/uwcfXCDEEyouUW1ZM3ZKQ3NVcWpNM3hxeGR3VWczemJoVFNMUWZoN0szbW5aWXhyaGNRRFl4RzJDaHR0cHM6Ly9pcGZzLmlvL2lwZnMvUW1ZM3ZKQ3NVcWpNM3hxeGR3VWczemJoVFNMUWZoN0szbW5aWXhyaGNRRFl4Rzo9dGFnczo7bWV0YWRhdGE6UW1SY1A5NGtYcjV6WmpSR3ZpN21KNnVuN0xweFVoWVZSNFI0UnBpY3h6Z1lrdA==",
        ];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTNFTCreate",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({
            logs: transactionLogs,
        });

        const outcome = parser.parseNftCreate(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].tokenIdentifier, identifier);
        assert.equal(outcome[0].nonce, nonce);
        assert.equal(outcome[0].initialQuantity, initialQuantity);
    });

    it("should test parse local mint", () => {
        const identifier = "AAA-29c4c9";
        const base64Identifier = Buffer.from(identifier).toString("base64");
        const nonce = BigInt(0);
        const mintedSupply = BigInt(100000);

        const encodedTopics = [base64Identifier, "", "AYag"];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTLocalMint",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({
            logs: transactionLogs,
        });

        const outcome = parser.parseLocalMint(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].userAddress, event.address);
        assert.equal(outcome[0].tokenIdentifier, identifier);
        assert.equal(outcome[0].nonce, nonce);
        assert.equal(outcome[0].mintedSupply, mintedSupply);
    });

    it("should test parse local burn", () => {
        const identifier = "AAA-29c4c9";
        const base64Identifier = Buffer.from(identifier).toString("base64");
        const nonce = BigInt(0);
        const burntSupply = BigInt(100000);

        const encodedTopics = [base64Identifier, "", "AYag"];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTLocalBurn",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({
            logs: transactionLogs,
        });

        const outcome = parser.parseLocalBurn(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].userAddress, event.address);
        assert.equal(outcome[0].tokenIdentifier, identifier);
        assert.equal(outcome[0].nonce, nonce);
        assert.equal(outcome[0].burntSupply, burntSupply);
    });

    it("should test parse pause", () => {
        const identifier = "AAA-29c4c9";
        const base64Identifier = Buffer.from(identifier).toString("base64");

        const encodedTopics = [base64Identifier];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTPause",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({
            logs: transactionLogs,
        });

        const outcome = parser.parsePause(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].tokenIdentifier, identifier);
    });

    it("should test parse unpause", () => {
        const identifier = "AAA-29c4c9";
        const base64Identifier = Buffer.from(identifier).toString("base64");

        const encodedTopics = [base64Identifier];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTUnPause",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({
            logs: transactionLogs,
        });

        const outcome = parser.parseUnpause(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].tokenIdentifier, identifier);
    });

    it("should test parse freeze", () => {
        const identifier = "AAA-29c4c9";
        const base64Identifier = Buffer.from(identifier).toString("base64");
        const nonce = BigInt(0);
        const balance = BigInt(10000000);
        const address = "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8";

        const encodedTopics = [base64Identifier, "", "mJaA", "ATlHLv9ohncamC8wg9pdQh8kwpGB5jiIIo3IHKYNaeE="];
        const event = new TransactionEvent({
            address: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            identifier: "DCDTFreeze",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            events: [event],
        });

        const scResult = new SmartContractResult({
            sender: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            receiver: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            data: Buffer.from("RVNEVEZyZWV6ZUA0MTQxNDEyZDMyMzk2MzM0NjMzOQ==", "base64"),
            logs: transactionLogs,
        });

        const txOutcome = new TransactionOutcome({
            smartContractResults: [scResult],
        });

        const outcome = parser.parseFreeze(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].userAddress, address);
        assert.equal(outcome[0].tokenIdentifier, identifier);
        assert.equal(outcome[0].nonce, nonce);
        assert.equal(outcome[0].balance, balance);
    });

    it("should test parse unfreeze", () => {
        const identifier = "AAA-29c4c9";
        const base64Identifier = Buffer.from(identifier).toString("base64");
        const nonce = BigInt(0);
        const balance = BigInt(10000000);
        const address = "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8";

        const encodedTopics = [base64Identifier, "", "mJaA", "ATlHLv9ohncamC8wg9pdQh8kwpGB5jiIIo3IHKYNaeE="];
        const event = new TransactionEvent({
            address: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            identifier: "DCDTUnFreeze",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            events: [event],
        });

        const scResult = new SmartContractResult({
            sender: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            receiver: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            data: Buffer.from("RVNEVEZyZWV6ZUA0MTQxNDEyZDMyMzk2MzM0NjMzOQ==", "base64"),
            logs: transactionLogs,
        });

        const txOutcome = new TransactionOutcome({
            smartContractResults: [scResult],
        });

        const outcome = parser.parseUnfreeze(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].userAddress, address);
        assert.equal(outcome[0].tokenIdentifier, identifier);
        assert.equal(outcome[0].nonce, nonce);
        assert.equal(outcome[0].balance, balance);
    });

    it("should test parse wipe", () => {
        const identifier = "AAA-29c4c9";
        const base64Identifier = Buffer.from(identifier).toString("base64");
        const nonce = BigInt(0);
        const balance = BigInt(10000000);
        const address = "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8";

        const encodedTopics = [base64Identifier, "", "mJaA", "ATlHLv9ohncamC8wg9pdQh8kwpGB5jiIIo3IHKYNaeE="];
        const event = new TransactionEvent({
            address: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            identifier: "DCDTWipe",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            events: [event],
        });

        const scResult = new SmartContractResult({
            sender: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzllls29jpxv",
            receiver: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            data: Buffer.from("RVNEVEZyZWV6ZUA0MTQxNDEyZDMyMzk2MzM0NjMzOQ==", "base64"),
            logs: transactionLogs,
        });

        const txOutcome = new TransactionOutcome({
            smartContractResults: [scResult],
        });

        const outcome = parser.parseWipe(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].userAddress, address);
        assert.equal(outcome[0].tokenIdentifier, identifier);
        assert.equal(outcome[0].nonce, nonce);
        assert.equal(outcome[0].balance, balance);
    });

    it("should test parse update attributes", () => {
        const identifier = "NFT-f01d1e";
        const base64Identifier = Buffer.from(identifier).toString("base64");
        const nonce = BigInt(1);
        const attributes = "metadata:ipfsCID/test.json;tags:tag1,tag2";
        const base64Attributes = Buffer.from(attributes).toString("base64");

        const encodedTopics = [base64Identifier, "AQ==", "", base64Attributes];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTNFTUpdateAttributes",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({
            logs: transactionLogs,
        });

        const outcome = parser.parseUpdateAttributes(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].tokenIdentifier, identifier);
        assert.equal(outcome[0].nonce, nonce);
        assert.equal(Buffer.from(outcome[0].attributes).toString(), attributes);
    });

    it("should test parse add quantity", () => {
        const identifier = "NFT-f01d1e";
        const base64Identifier = Buffer.from(identifier).toString("base64");
        const nonce = BigInt(1);
        const addedQuantity = BigInt(10);

        const encodedTopics = [base64Identifier, "AQ==", "Cg=="];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTNFTAddQuantity",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({
            logs: transactionLogs,
        });

        const outcome = parser.parseAddQuantity(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].tokenIdentifier, identifier);
        assert.equal(outcome[0].nonce, nonce);
        assert.equal(outcome[0].addedQuantity, addedQuantity);
    });

    it("should test parse burn quantity", () => {
        const identifier = "NFT-f01d1e";
        const base64Identifier = Buffer.from(identifier).toString("base64");
        const nonce = BigInt(1);
        const burntQuantity = BigInt(16);

        const encodedTopics = [base64Identifier, "AQ==", "EA=="];
        const event = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "DCDTNFTBurn",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const transactionLogs = new TransactionLogs({
            address: "moa1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssfq94h8",
            events: [event],
        });

        const txOutcome = new TransactionOutcome({
            logs: transactionLogs,
        });

        const outcome = parser.parseBurnQuantity(txOutcome);
        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].tokenIdentifier, identifier);
        assert.equal(outcome[0].nonce, nonce);
        assert.equal(outcome[0].burntQuantity, burntQuantity);
    });
});
