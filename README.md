# 🛡️ RugLens

**RugLens** is an advanced real-time smart contract threat detector built for the [Venn Network](https://venn.build). It scans deployed bytecode and transaction traces to identify high-risk rugpull behaviors — before damage occurs.

---

## 🔍 Overview

Rugpulls often embed malicious behavior inside contract bytecode or abuse runtime calls post-deployment. RugLens solves this by combining:

- 🔬 Static bytecode analysis for malicious opcodes
- 🧠 Function signature scanning for risky admin logic
- 🛰️ Trace-based behavior analysis for live threats (ETH drains, function misuse)

---

## 🧠 What RugLens Detects

| Type                  | Example Risk                             | Detection Method        |
|-----------------------|-------------------------------------------|--------------------------|
| `SELFDESTRUCT`        | Kill-switch to drain funds                | Bytecode opcode match    |
| `DELEGATECALL`        | Arbitrary code injection                  | Bytecode opcode match    |
| `transferOwnership()` | Stealth ownership transfer                | Signature + trace match  |
| `mint()`              | Infinite supply risk                      | Signature match          |
| ETH inflow            | Large unexpected ETH sent to contract     | Trace pattern detection  |

---

## ⚙️ How It Works

RugLens exposes a single static method:

```ts
DetectionService.detect(request: DetectionRequest): DetectionResponse
```

It returns a response like:

```ts
{
  detected: true,
  message: "RugLens flagged 3 risks:\n- [HIGH] Contains SELFDESTRUCT opcode\n- [MEDIUM] transferOwnership() called at trace index 0"
}
```

---

## 🚀 Quickstart

### Clone & Install

```bash
git clone https://github.com/Abhi270303/ruglens.git
cd ruglens
npm install
```

### Run the Detector

```bash
npm run dev
```

---

## 🧪 Run Tests

```bash
npx jest
```

Unit tests include:
- Bytecode analysis (opcodes, function selectors)
- Trace simulations (ownership transfers, value flows)
- Clean contract verification

---

## 🧩 Project Structure

```
src/
├── modules/
│   └── detection-module/
│       ├── service.ts       # Detection logic
│       ├── dtos/            # Request/response schemas
│       └── types/           # Custom trace typing
tests/
└── app.spec.ts              # Full detection test suite
```

---

## 🛠 Built With

- TypeScript
- Jest (test suite)
- ts-node & reflect-metadata
- Designed for Venn Security Infrastructure

---

## 🔒 Designed For

- Smart contract auditors
- On-chain monitoring teams
- Post-deployment threat detection
- Continuous contract verification

---

## 📎 Resources

- [Venn Documentation](https://docs.venn.build)
- [Telegram: Venn Builders](https://t.me/vennbuilders)
- [How to Build Custom Detectors](https://docs.venn.build/venn-network/getting-started/security-teams/build-custom-detector)


---
