import { DetectionRequest, DetectionResponse } from './dtos'

/**
 * DetectionService
 *
 * Core class that processes a DetectionRequest and returns a DetectionResponse.
 * This is where your custom rugpull logic is implemented.
 */
export class DetectionService {
    /**
     * Static detection method
     * Analyzes the smart contract bytecode for potential rugpull indicators
     *
     * @param request DetectionRequest — contains metadata and bytecode of the contract
     * @returns DetectionResponse — flags if malicious, with reason and severity
     */
    public static detect(request: DetectionRequest): DetectionResponse {
        // Ensure bytecode is available and normalized to lowercase for matching
        const bytecode = (request.bytecode || '').toLowerCase()

        // Initialize a list to collect any suspicious indicators found
        const flags: string[] = []

        // --- 🚩 RUGPULL INDICATORS ---
        
        // Check for 'SELFDESTRUCT' opcode (hex: 0xff) — risky for fund drains
        if (bytecode.includes('ff')) {
            flags.push('Contains SELFDESTRUCT opcode')
        }

        // Check for 'DELEGATECALL' opcode (hex: 0xf4) — allows code injection risk
        if (bytecode.includes('f4')) {
            flags.push('Uses DELEGATECALL opcode')
        }

        // Check for 'transfer(address,uint256)' — ERC-20 transfer function (sig: 0xa9059cbb)
        if (bytecode.includes('a9059cbb')) {
            flags.push('Includes ERC-20 transfer() function')
        }

        // Check for 'approve(address,uint256)' — ERC-20 approve function (sig: 0x095ea7b3)
        if (bytecode.includes('095ea7b3')) {
            flags.push('Includes ERC-20 approve() function')
        }

        // --- 🧠 Evaluation ---

        // Mark contract as malicious if any rugpull indicators are found
        const isMalicious = flags.length > 0

        // Construct and return the final DetectionResponse object
        return new DetectionResponse({
            request,
            detectionInfo: {
                detected: isMalicious, // true or false
                message: isMalicious ? flags.join('; ') : 'No rugpull indicators detected',
            },
        })
    }
}
