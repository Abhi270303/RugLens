import 'reflect-metadata'
import { DetectionService } from '../src/modules/detection-module/service'
import { DetectionRequest } from '../src/modules/detection-module/dtos'


describe('Rugpull Detector', () => {
  it('should flag bytecode with SELFDESTRUCT opcode as malicious', () => {
    const mockRequest: DetectionRequest = {
      chainId: 1,
      hash: '0x123',
      trace: {
        from: '0xabc123abc123abc123abc123abc123abc123abc1',
        to: '0xdef456def456def456def456def456def456def4',
        gas: '0x0',
        gasUsed: '0x0',
        input: '0x',
        pre: {},
        post: {},
      },
      bytecode: '6080604052ff' // contains `ff` opcode
    }

    const result = DetectionService.detect(mockRequest)

    expect(result.detected).toBe(true)
    expect(result.message).toContain('SELFDESTRUCT')
  })

  it('should not flag clean bytecode', () => {
    const mockRequest: DetectionRequest = {
      chainId: 1,
      hash: '0x456',
      trace: {
        from: '0xabc123abc123abc123abc123abc123abc123abc1',
        to: '0xdef456def456def456def456def456def456def4',
        gas: '0x0',
        gasUsed: '0x0',
        input: '0x',
        pre: {},
        post: {},
      },
      bytecode: '608060405234801561001057600080fd5b5060' // no malicious opcodes
    }

    const result = DetectionService.detect(mockRequest)

    expect(result.detected).toBe(false)
    expect(result.message).toBe('No rugpull indicators detected')
  })
})
