// Configuration Hardhat de NOORTRACE, sur le modèle de celle de noorchain-core.
// Le réseau « noorcore » est l'instance dédiée de noorcore (JSON-RPC sur le
// port 8645) ; la clé du déployeur vient de la variable NOOR_PRIVATE_KEY.
import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers],
  solidity: {
    version: "0.8.20",
    settings: {
      viaIR: true,
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    // Réseau Hardhat en mémoire, nommé explicitement « hardhat » : Hardhat 3 ne
    // définit par défaut que « default », « localhost » et « node ».
    hardhat: {
      type: "edr-simulated",
    },
    noorcore: {
      type: "http",
      url: "http://127.0.0.1:8645",
      accounts: process.env.NOOR_PRIVATE_KEY ? [process.env.NOOR_PRIVATE_KEY] : [],
    },
  },
  paths: {
    sources: "contracts",
    cache: "hh-cache",
    artifacts: "hh-artifacts",
    tests: "test",
  },
});
