import { DetectionRequest, DetectionResponse } from './dtos'
import { TraceCall } from '../../types/http.types'

interface RiskFinding {
    type: string
    severity: 'HIGH' | 'MEDIUM' | 'LOW'
    reason: string
    traceIndex?: number
}

export class DetectionService {
    private static readonly OPCODES = {
        SELFDESTRUCT: 'ff',
        DELEGATECALL: 'f4',
    }

    private static readonly FUNCTION_SIGS = {
        TRANSFER: 'a9059cbb',
        APPROVE: '095ea7b3',
        TRANSFER_OWNERSHIP: 'f2fde38b', // no 0x prefix — we strip it from trace call inputs
        PAUSE: '8456cb59',
        MINT: '40c10f19',
    }

    public static detect(request: DetectionRequest): DetectionResponse {
        const bytecode = (request.bytecode || '').toLowerCase()
        const flags: RiskFinding[] = []

        // -------- BYTECODE STATIC ANALYSIS --------
        if (bytecode.includes(this.OPCODES.SELFDESTRUCT)) {
            flags.push({ type: 'SELFDESTRUCT', severity: 'HIGH', reason: 'Contains SELFDESTRUCT opcode - risky for fund drain' })
        }
        if (bytecode.includes(this.OPCODES.DELEGATECALL)) {
            flags.push({ type: 'DELEGATECALL', severity: 'HIGH', reason: 'Uses DELEGATECALL - allows injecting external logic' })
        }
        if (bytecode.includes(this.FUNCTION_SIGS.TRANSFER)) {
            flags.push({ type: 'TRANSFER', severity: 'LOW', reason: 'Includes ERC-20 transfer() function' })
        }
        if (bytecode.includes(this.FUNCTION_SIGS.APPROVE)) {
            flags.push({ type: 'APPROVE', severity: 'LOW', reason: 'Includes ERC-20 approve() function' })
        }
        if (bytecode.includes(this.FUNCTION_SIGS.TRANSFER_OWNERSHIP)) {
            flags.push({ type: 'OWNERSHIP', severity: 'MEDIUM', reason: 'transferOwnership function present' })
        }
        if (bytecode.includes(this.FUNCTION_SIGS.PAUSE)) {
            flags.push({ type: 'PAUSABLE', severity: 'MEDIUM', reason: 'pause() function found' })
        }
        if (bytecode.includes(this.FUNCTION_SIGS.MINT)) {
            flags.push({ type: 'MINT', severity: 'HIGH', reason: 'mint() function found - potential for token inflation' })
        }

        // -------- TRACE-BASED BEHAVIORAL ANALYSIS --------
        const traceCalls = request.trace?.calls ?? []
        traceCalls.forEach((call, i) => {
            const input = (call.input || '').toLowerCase()

            // Detect ETH transfers to contract
            const value = BigInt(call.value || '0')
            const targetAddress = request.address?.toLowerCase()
            if (value > 0n && call.to?.toLowerCase() === targetAddress) {
                flags.push({
                    type: 'FUNDS_IN',
                    severity: 'MEDIUM',
                    reason: `Contract received ${value} wei from ${call.from}`,
                    traceIndex: i,
                })
            }

            // Detect transferOwnership in trace
            if (input.startsWith('0x' + this.FUNCTION_SIGS.TRANSFER_OWNERSHIP)) {
                flags.push({
                    type: 'TRACE_OWNERSHIP_TRANSFER',
                    severity: 'MEDIUM',
                    reason: `transferOwnership() called at trace index ${i}`,
                    traceIndex: i,
                })
            }
        })

        const detected = flags.length > 0
        const message = detected
            ? `RugLens flagged ${flags.length} risks:\n` + flags.map(f => `- [${f.severity}] ${f.reason}`).join('\n')
            : 'No rugpull indicators detected'

        return new DetectionResponse({
            request,
            detectionInfo: {
                detected,
                message
            }
        })
    }
}
