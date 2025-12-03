import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;

  const deployedVaultWars = await deploy("VaultWars", {
    from: deployer,
    log: true,
  });

  console.log(`VaultWars contract: `, deployedVaultWars.address);
};
export default func;
func.id = "deploy_vaultWars"; // id required to prevent reexecution
func.tags = ["VaultWars"];
