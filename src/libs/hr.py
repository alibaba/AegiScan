import ida_hexrays as hr

mov_like_insn = Mov = [ 'm_ldc', 'm_mov', \
        'm_xds', 'm_xdu', 'm_low', 'm_high', \
        'm_neg', 'm_lnot', 'm_bnot', \
        'm_i2f', 'm_f2i', 'm_f2u', 'm_f2f', 'm_fneg', \
        'm_sets']
m_mov_like = set()
# 'm_ldx', 'm_stx' need further process
arithmetic_insn = {'add', 'sub', 'mul', 'udiv', 'sdiv', 'umod', 'smod', 'or', 'and', 'xor', 'setp', 'setnz', 'setz',
                   'setae', 'setb', 'seta', 'setbe', 'setg', 'setge', 'setl', 'setle', 'seto', 'shl', 'shr', 'sar',
                   'cfadd', 'ofadd', 'cfshl'}
m_arithmetic = set()

m_jmp0 = {hr.m_goto}
m_jmp1 = {hr.m_jcnd, hr.m_jtbl, hr.m_ijmp} # TODO
m_jmp2 = set()

for attr in dir(hr):
    val = getattr(hr, attr)
    if attr.startswith('m_j'):
        if  val not in m_jmp1:
            m_jmp2.add(val)

    elif attr[2:] in arithmetic_insn:
        m_arithmetic.add(val)

    elif attr in mov_like_insn:
        m_mov_like.add(val)

m_jmp = set.union(m_jmp0, m_jmp1, m_jmp2)

__all__ = ['m_arithmetic', 'm_jmp', 'm_jmp0', 'm_jmp1', 'm_jmp2']
