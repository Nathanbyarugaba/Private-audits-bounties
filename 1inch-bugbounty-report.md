**Inverted scale update formula in concentrated liquidity breaks invariant allowing economic exploitation**


Created on November 17, 2025

Location: src/instructions/XYCConcentrate.sol

**Description**
The _updateScales function updates the deltaScale with an inverted formula that breaks the concentrated liquidity invariant. According to invariant 10, the scaled invariant should remain constant:

```solidity
prevScale * (balanceIn_before * balanceOut_before) == newScale * ((balanceIn_before + amountIn) * (balanceOut_before - amountOut))
This means: newScale = prevScale * inv / newInv
```
However, the implementation does the opposite

```solidity
function _updateScales(Context memory ctx) private {
    require(ctx.swap.amountIn > 0 && ctx.swap.amountOut > 0, ConcentrateExpectedSwapAmountComputationAfterRunLoop(ctx.swap.amountIn, ctx.swap.amountOut));

    if (!ctx.vm.isStaticContext) {
        uint256 inv = ctx.swap.balanceIn * ctx.swap.balanceOut;
        uint256 newInv = (ctx.swap.balanceIn + ctx.swap.amountIn) * (ctx.swap.balanceOut - ctx.swap.amountOut);
        deltaScales[ctx.query.orderHash] = deltaScale(ctx.query.orderHash) * newInv / inv;
    }
}
```

The code computes newScale = prevScale * newInv / inv, which is the inverse of the required formula. This causes the scale to grow instead of shrink as liquidity is consumed. Since concentrated balance is calculated as balance + delta * deltaScale(orderHash) / ONE, an erroneously growing scale leads to artificially inflated liquidity. This breaks the economic model of concentrated liquidity and could allow the order to provide more tokens than the maker actually holds or intended to provide.

##Mathematical Proof
Invariant Requirement
The concentrated liquidity system maintains a scaled invariant that must remain constant:
```
prevScale * inv == newScale * newInv
Where:

inv = balanceIn_before * balanceOut_before (invariant before swap)
newInv = (balanceIn_before + amountIn) * (balanceOut_before - amountOut) (invariant after swap)
Derivation of Correct Formula
Starting from the invariant:

C
prevScale * inv = newScale * newInv
Solving for newScale:

=
newScale = (prevScale * inv) / newInv
Analysis of Current (Buggy) Formula
The current implementation computes:
=
newScale = prevScale * newInv / inv  //  INVERTED
Impact Analysis
When liquidity is consumed (swap with fees):

newInv > inv (invariant grows due to fees)
Correct formula: newScale = prevScale * inv / newInv
Since inv < newInv, we get newScale < prevScale ✓ (scale shrinks correctly)
Buggy formula: newScale = prevScale * newInv / inv
Since newInv > inv, we get newScale > prevScale ✗ (scale grows incorrectly)
Example Calculation
Given:

prevScale = 1e18
inv = 1000e18 * 2000e18 = 2e24
newInv = 1010e18 * 1990e18 = 2.0099e24 (after swap with fees)
Correct formula:

newScale = 1e18 * 2e24 / 2.0099e24 = 0.99507e18  ✓ (shrinks)
Buggy formula:


newScale = 1e18 * 2.0099e24 / 2e24 = 1.00495e18  ✗ (grows)
The buggy formula causes the scale to grow by ~0.5% when it should shrink by ~0.5%.
```
##Impact
1. Invariant Violation
The scaled invariant prevScale * inv == newScale * newInv is broken. In test cases:

Correct formula difference: ~5e43 (small, due to rounding)
Buggy formula difference: ~2.15e58 (orders of magnitude larger)
The buggy formula produces a difference that is ~430x larger than the correct formula.

2. Artificial Liquidity Inflation
Since concentratedBalance = balance + delta * deltaScale(orderHash) / ONE, an erroneously growing scale inflates the concentrated balance, making the system think there's more liquidity available than actually exists.

3. Economic Exploitation
The inflated scale creates taker-favorable mispricing:

Orders using XYCConcentrateGrowLiquidity* are funded/escrowed, so settlement succeeds
Mispricing from inflated deltaScale enables profitable trades vs market
Repeated swaps compound the scale growth, allowing continued extraction until order funds are depleted
4. Compounding Effect
The bug compounds over multiple swaps:

After 1 swap: Scale grows from 1e18 to 1.000066e18 (+0.0066%)
After 2 swaps: Scale grows to 1.000131e18 (+0.0131%)
After 3 swaps: Scale grows to 1.000194e18 (+0.0194%)
Each swap increases the scale, further inflating available liquidity.

5. Test Evidence
From the proof-of-concept test:

Scale grows instead of shrinks: Expected 999870813397129186, Actual 1000129203294205471
Invariant broken: Buggy formula produces ~430x larger difference than correct formula
Repeated swaps show compounding scale growth
Validation steps
I have attached the runnable proof of code PoC.md.

Complete Fixed Function
```solidity
function _updateScales(Context memory ctx) private {
    require(ctx.swap.amountIn > 0 && ctx.swap.amountOut > 0, ConcentrateExpectedSwapAmountComputationAfterRunLoop(ctx.swap.amountIn, ctx.swap.amountOut));

    if (!ctx.vm.isStaticContext) {
        uint256 inv = ctx.swap.balanceIn * ctx.swap.balanceOut;
        uint256 newInv = (ctx.swap.balanceIn + ctx.swap.amountIn) * (ctx.swap.balanceOut - ctx.swap.amountOut);
        deltaScales[ctx.query.orderHash] = deltaScale(ctx.query.orderHash) * inv / newInv;  // ✓ FIXED
    }
}
```
