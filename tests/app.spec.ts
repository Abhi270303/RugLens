import 'reflect-metadata'
import { DetectionService } from '../src/modules/detection-module/service'
import { DetectionRequest } from '../src/modules/detection-module/dtos'

describe('RugLens Detection — Real-Case Simulation', () => {
  it('flags SELFDESTRUCT and DELEGATECALL from bytecode', () => {
    const result = DetectionService.detect({
      chainId: 1,
      hash: '0xaaa',
      bytecode: '6080604052ff6040f4',
      trace: { from: '', to: '', gas: '0x0', gasUsed: '0x0', input: '', pre: {}, post: {}, calls: [] }
    })

    expect(result.detected).toBe(true)
    expect(result.message).toContain('SELFDESTRUCT')
    expect(result.message).toContain('DELEGATECALL')
  })

  it('flags transferOwnership in trace input', () => {
    const result = DetectionService.detect({
      chainId: 1,
      hash: '0xdd',
      address: '0x1',
      bytecode: '',
      trace: {
        from: '', to: '', gas: '0x0', gasUsed: '0x0', input: '', pre: {}, post: {},
        calls: [{
          from: '0xabc',
          to: '0x1',
          input: '0xf2fde38b000000000000000000000000abcdefabcdefabcdefabcdefabcdef',
          value: '0',
          gasUsed: '0x0'
        }]
      }
    })

    expect(result.detected).toBe(true)
    expect(result.message).toContain('transferOwnership() called')
  })

  it('flags ETH transfer to contract in trace', () => {
    const result = DetectionService.detect({
      chainId: 1,
      hash: '0xcc',
      address: '0xdeadbeef00000000000000000000000000000001',
      bytecode: '',
      trace: {
        from: '', to: '', gas: '0x0', gasUsed: '0x0', input: '', pre: {}, post: {},
        calls: [{
          from: '0xabc',
          to: '0xdeadbeef00000000000000000000000000000001',
          input: '0x',
          value: '1000000000000000000',
          gasUsed: '0x0'
        }]
      }
    })

    expect(result.detected).toBe(true)
    expect(result.message).toContain('Contract received')
  })

  it('does not flag safe bytecode or trace', () => {
    const result = DetectionService.detect({
      chainId: 1,
      hash: '0xee',
      bytecode: '608060405234801561001057600080fd5b5060',
      trace: { from: '', to: '', gas: '0x0', gasUsed: '0x0', input: '', pre: {}, post: {}, calls: [] }
    })

    expect(result.detected).toBe(false)
    expect(result.message).toBe('No rugpull indicators detected')
  })
})
