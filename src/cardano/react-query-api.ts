import { useQuery } from "@tanstack/react-query";
import type {
  Cardano,
  PaymentAddress,
  TransactionOutput,
  Reward_Aggregate,
  Withdrawal_Aggregate,
  StakeRegistration_Aggregate,
  StakeDeregistration_Aggregate,
  Delegation,
  StakePool,
  Transaction,
} from "@cardano-graphql/client-ts/api";
import type { Recipient } from "./multiplatform-lib";
import axios, { AxiosResponse } from "axios";

type Assets = Map<string, bigint>;

type Value = {
  lovelace: bigint;
  assets: Assets;
};

const baseURL = process.env.NEXT_PUBLIC_BACKEND_API || "";
const axiosInstance = axios.create({
  baseURL,
});

const urls = {
  get: {
    stakepool: (poolid: string | number | undefined) =>
      poolid ? `/stake-pools/${poolid}` : `/stake-pools`,
  },
  post: {
    paymentAddress: () => `/payment-address`,
    transactionSummary: () => `/transactions-summary`,
    summary: () => `/summary`,
    utxoSummary: () => `/utxo-summary`,
  },
};

type TUtxoSummaryQueryParams = { addresses: string[]; rewardAddress: string };
type TUtxoSummaryQueryResult = {
  data: {
    utxos: TransactionOutput[];
    cardano: Cardano;
    rewards_aggregate: Reward_Aggregate;
    withdrawals_aggregate: Withdrawal_Aggregate;
    stakeRegistrations_aggregate: StakeRegistration_Aggregate;
    stakeDeregistrations_aggregate: StakeDeregistration_Aggregate;
    delegations: Delegation[];
  };
};
const getUTxoSummary = (data: TUtxoSummaryQueryParams) =>
  axiosInstance.post(urls.post.utxoSummary(), data);

const useUTxOSummaryQuery = (data: TUtxoSummaryQueryParams) =>
  useQuery<
    AxiosResponse<TUtxoSummaryQueryResult>,
    unknown,
    TUtxoSummaryQueryResult['data']
  >({
    queryKey: ["utxo-summary"],
    queryFn: () => getUTxoSummary(data),
    select: (data) => data.data.data,
  });

type TPaymentAddressQueryParams = { addresses: string[] };
type TPaymentAddressQueryResult = {
  data: { paymentAddresses: PaymentAddress[] };
};
const getPaymentAddress = (data: TPaymentAddressQueryParams) =>
  axiosInstance.post(urls.post.paymentAddress(), data);

const usePaymentAddressesQuery = (data: TPaymentAddressQueryParams) =>
  useQuery<
    AxiosResponse<TPaymentAddressQueryResult>,
    unknown,
    TPaymentAddressQueryResult['data']
  >({
    queryKey: ["payment-address"],
    queryFn: () => getPaymentAddress(data),
    select: (data) => data.data.data,
    enabled: data.addresses.length > 0,
  });

type TSummaryQueryParams = { addresses: string[]; rewardAddress: string };
type TSummaryQueryResult = {
  data: {
    paymentAddresses: PaymentAddress[];
    rewards_aggregate: Reward_Aggregate;
    withdrawals_aggregate: Withdrawal_Aggregate;
    stakeRegistrations_aggregate: StakeRegistration_Aggregate;
    stakeDeregistrations_aggregate: StakeDeregistration_Aggregate;
    delegations: Delegation[];
  };
};
const getSummary = (data: TSummaryQueryParams) =>
  axiosInstance.post(urls.post.summary(), data);

const useSummaryQuery = (data: TSummaryQueryParams) =>
  useQuery<AxiosResponse<TSummaryQueryResult>, unknown, TSummaryQueryResult['data']>({
    queryKey: ["summary"],
    queryFn: () => getSummary(data),
    select: (data) => data.data.data,
  });

type TStakePoolsQueryResult = { data: { stakePools: StakePool[] } };
const getStakePools = (id: string | number | undefined) =>
  axiosInstance.get(urls.get.stakepool(id));

const useStakePoolsQuery = (id: string | number | undefined) =>
  useQuery<
    AxiosResponse<TStakePoolsQueryResult>,
    unknown,
    TStakePoolsQueryResult['data']
  >({
    queryKey: ["stake-pool"],
    queryFn: () => getStakePools(id),
    select: (data) => data.data.data,
  });

type TTransactionSummaryQueryParams = { hashes: string[] };
type TTransactionSummaryQueryResult = { data: { transactions: Transaction[] } };
const getTransactionSummary = (data: TTransactionSummaryQueryParams) =>
  axiosInstance.post(urls.post.transactionSummary(), data);

const useTransactionSummaryQuery = (data: TTransactionSummaryQueryParams) =>
  useQuery<
    AxiosResponse<TTransactionSummaryQueryResult>,
    unknown,
    TTransactionSummaryQueryResult['data']
  >({
    queryKey: ["TransactionSummary"],
    queryFn: () => getTransactionSummary(data),
    select: (data) => data.data.data,
  });

// UTILS
const getPolicyId = (assetId: string) => assetId.slice(0, 56);
const getAssetName = (assetId: string) => assetId.slice(56);
const decodeASCII = (assetName: string): string => {
  return Buffer.from(assetName, "hex").toString("ascii");
};

const sumValues = (values: Value[]): Value =>
  values.reduce(
    (acc, value) => {
      const assets = new Map(acc.assets);
      value.assets.forEach((quantity, id) =>
        assets.set(id, (assets.get(id) ?? BigInt(0)) + quantity)
      );

      return {
        lovelace: acc.lovelace + value.lovelace,
        assets,
      };
    },
    { lovelace: BigInt(0), assets: new Map() }
  );

const getValueFromTransactionOutput = (output: TransactionOutput): Value => {
  const assets: Assets = new Map();

  output.tokens.forEach(({ asset, quantity }) => {
    const { assetId } = asset;
    const value = (assets.get(assetId) ?? BigInt(0)) + BigInt(quantity);
    assets.set(assetId, value);
  });

  return {
    lovelace: BigInt(output.value),
    assets,
  };
};

const getRecipientFromTransactionOutput = (
  output: TransactionOutput
): Recipient => {
  return {
    address: output.address,
    value: getValueFromTransactionOutput(output),
  };
};

const getBalanceByUTxOs = (utxos: TransactionOutput[]): Value =>
  sumValues(utxos.map(getValueFromTransactionOutput));

function getBalanceByPaymentAddresses(
  paymentAddresses: PaymentAddress[]
): Value {
  const balance: Value = {
    lovelace: BigInt(0),
    assets: new Map(),
  };

  paymentAddresses.forEach((paymentAddress) => {
    paymentAddress.summary?.assetBalances?.forEach((assetBalance) => {
      if (assetBalance) {
        const { assetId } = assetBalance.asset;
        const quantity = assetBalance.quantity;
        if (assetId === "ada") {
          balance.lovelace = balance.lovelace + BigInt(quantity);
          return;
        }
        const value = balance.assets.get(assetId) ?? BigInt(0);
        balance.assets.set(assetId, value + BigInt(quantity));
      }
    });
  });

  return balance;
}

function isRegisteredOnChain(
  stakeRegistrationsAggregate: StakeRegistration_Aggregate,
  stakeDeregistrationsAggregate: StakeDeregistration_Aggregate
): boolean {
  const registrationCount = BigInt(
    stakeRegistrationsAggregate.aggregate?.count ?? "0"
  );
  const deregistrationCount = BigInt(
    stakeDeregistrationsAggregate.aggregate?.count ?? "0"
  );
  return registrationCount > deregistrationCount;
}

function getCurrentDelegation(
  stakeRegistrationsAggregate: StakeRegistration_Aggregate,
  stakeDeregistrationsAggregate: StakeDeregistration_Aggregate,
  delegations: Delegation[]
): Delegation | undefined {
  if (
    isRegisteredOnChain(
      stakeRegistrationsAggregate,
      stakeDeregistrationsAggregate
    )
  )
    return delegations[0];
}

function getAvailableReward(
  rewardsAggregate: Reward_Aggregate,
  withdrawalsAggregate: Withdrawal_Aggregate
): bigint {
  const rewardSum: bigint = BigInt(rewardsAggregate.aggregate?.sum.amount ?? 0);
  const withdrawalSum: bigint = BigInt(
    withdrawalsAggregate.aggregate?.sum.amount ?? 0
  );
  return rewardSum - withdrawalSum;
}

type RecipientRegistry = Map<string, Map<number, Recipient>>;

const collectTransactionOutputs = (
  transactions: Transaction[]
): RecipientRegistry =>
  transactions.reduce((collection: RecipientRegistry, transaction) => {
    const { hash, outputs } = transaction;
    const subCollection: Map<number, Recipient> =
      collection.get(hash) ?? new Map();
    outputs.forEach((output) => {
      if (output)
        subCollection.set(
          output.index,
          getRecipientFromTransactionOutput(output)
        );
    });
    return collection.set(hash, subCollection);
  }, new Map());


export type { Value, RecipientRegistry };
export {
  decodeASCII,
  getBalanceByUTxOs,
  getPolicyId,
  getAssetName,
  getBalanceByPaymentAddresses,
  useUTxOSummaryQuery,
  usePaymentAddressesQuery,
  useSummaryQuery,
  getCurrentDelegation,
  getAvailableReward,
  useStakePoolsQuery,
  isRegisteredOnChain,
  sumValues,
  useTransactionSummaryQuery,
  collectTransactionOutputs,
};
