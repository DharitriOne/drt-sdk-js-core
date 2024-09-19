import { assert } from "chai";
import { Address } from "../address";
import { b64TopicsToBytes } from "../testutils";
import { DelegationTransactionsOutcomeParser } from "./delegationTransactionsOutcomeParser";
import { SmartContractResult, TransactionEvent, TransactionLogs, TransactionOutcome } from "./resources";

describe("test delegation transactions outcome parser", () => {
    const parser = new DelegationTransactionsOutcomeParser();

    it("should test parseCreateNewDelegationContract ", () => {
        const contractAddress = Address.fromBech32("moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqy8llllshjzgvy");
        let encodedTopics = [
            "Q8M8GTdWSAAA",
            "Q8M8GTdWSAAA",
            "AQ==",
            "Q8M8GTdWSAAA",
            "AAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAABD///8=",
        ];

        const delegateEvent = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "delegate",
            topics: b64TopicsToBytes(encodedTopics),
        });

        encodedTopics = [
            "AAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAABD///8=",
            "PDXX6ssamaSgzKpTfvDMCuEJ9B9sK0AiA+Yzv7sHH1w=",
        ];
        const scDeployEvent = new TransactionEvent({
            address: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqy8llllshjzgvy",
            identifier: "SCDeploy",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const logs = new TransactionLogs({ events: [delegateEvent, scDeployEvent] });

        encodedTopics = ["b2g6sUl6beG17FCUIkFwCOTGJjoJJi5SjkP2077e6xA="];
        const scResultEvent = new TransactionEvent({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            identifier: "completedTxEvent",
            topics: b64TopicsToBytes(encodedTopics),
        });

        const scResultLog = new TransactionLogs({
            address: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            events: [scResultEvent],
        });

        const scResult = new SmartContractResult({
            sender: "moa1qqqqqqqqqqqqqqqpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqylllsjrx4c2",
            receiver: "moa18s6a06ktr2v6fgxv4ffhauxvptssnaqlds45qgsrucemlwc8rawqevhvh6",
            data: Buffer.from(
                "QDZmNmJAMDAwMDAwMDAwMDAwMDAwMDAwMDEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxMGZmZmZmZg==",
                "base64",
            ),
            logs: scResultLog,
        });

        const txOutcome = new TransactionOutcome({ smartContractResults: [scResult], logs: logs });

        const outcome = parser.parseCreateNewDelegationContract(txOutcome);

        assert.lengthOf(outcome, 1);
        assert.equal(outcome[0].contractAddress, contractAddress.toBech32());
    });
});
