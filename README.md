# Dharitri SDK for JavaScript and TypeScript

Dharitri SDK for JavaScript and TypeScript (written in TypeScript).

## Documentation

-   [Cookbook](https://docs.dharitri.com/sdk-and-tools/sdk-js/sdk-js-cookbook/)
-   [Auto-generated documentation](https://DharitriOne.github.io/drt-sdk-js-core/)

## Distribution

[npm](https://www.npmjs.com/package/@dharitri-sdk/core)

## Installation

`sdk-core` is delivered via **npm** and it can be installed as follows:

```
npm install @dharitri-sdk/core
```

## Development

Feel free to skip this section if you are not a contributor.

### Prerequisites

`browserify` and `esmify` are required to compile the browser-friendly versions of `sdk-core`. They can be installed as follows:

```
npm install --global browserify
npm install esmify --no-save
```

### Building the library

In order to compile the library, run the following:

```
npm install
npm run compile
npm run compile-browser
```

### Running the tests

In order to run the tests **on NodeJS**, do as follows:

```
npm run tests-unit
npm run tests-localnet
npm run tests-devnet
npm run tests-testnet
```

Before running the tests **in the browser**, make sure you have the package `http-server` installed globally.

```
npm install --global http-server
```

In order to run the tests **in the browser**, do as follows:

```
make clean && npm run browser-tests
```

For the `localnet` tests, make sure you have a _local testnet_ up & running. In order to start a _local testnet_, follow [this](https://docs.dharitri.com/developers/setup-local-testnet/).
