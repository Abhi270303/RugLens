
# 🛡️ RugLens

**RugLens** is a smart contract bytecode analyzer that detects rugpull patterns in real-time. Built using [Venn Network](https://venn.build), it empowers security teams with post-deployment protection through opcode-level analysis.

---

## 🔍 Vision

RugLens detects malicious smart contracts in real-time by analyzing bytecode for rugpull patterns, enabling proactive on-chain protection and continuous threat monitoring within the Venn Network.

---

## ⚙️ Features

- Detects high-risk opcodes like `SELFDESTRUCT` and `DELEGATECALL`
- Flags ERC-20 `transfer` and `approve` abuse vectors
- Bytecode normalization and pattern matching
- Structured `DetectionRequest` and `DetectionResponse` models
- Built-in test suite using Jest
- Ready for Docker or manual Node.js deployment

---

## 🧠 Detection Logic

```ts
if (bytecode.includes('ff')) flags.push('Contains SELFDESTRUCT opcode');
if (bytecode.includes('f4')) flags.push('Uses DELEGATECALL opcode');
if (bytecode.includes('a9059cbb')) flags.push('Includes ERC-20 transfer()');
if (bytecode.includes('095ea7b3')) flags.push('Includes ERC-20 approve()');
```

---

## 🚀 Getting Started

### Clone & Install

```bash
git clone https://github.com/Abhi270303/ruglens.git
cd ruglens
npm install
```

### Run Detector

```bash
npm run dev
npm start
```

### Test

```bash
npx jest
```

---

## 📦 Project Structure

- `service.ts` — Core detection logic
- `detect.ts` — Entry point for Venn detector runtime
- `detect-request.ts` / `detect-response.ts` — DTO definitions
- `tests/` — Unit tests with sample payloads

---

## 🛠 Built With

- TypeScript
- Express.js
- Jest
- Venn SDK-compatible architecture

---

## 📎 Resources

- [Venn Detector Docs](https://docs.venn.build/venn-network/getting-started/security-teams/build-custom-detector)
- [Join the Venn Security Team](https://www.venn.build/join/security-team)
- [Telegram Support](https://t.me/vennbuilders)

---

## 🧢 License

MIT © Your Team Name

---

