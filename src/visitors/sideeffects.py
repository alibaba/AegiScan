import ida_hexrays as hr

from collections import Counter


class SideEffectsRecorder:
    def __init__(self, mba):
        self.mba = mba
        self.side_effects = {}

    def parse(self):
        for i in range(1, self.mba.qty):
            mblock = self.mba.get_mblock(i)
            counter = Counter(self.count_write_for_block(mblock))
            written = set(idx for idx, count in counter.items() if count == 1)
            if len(written):
                self.side_effects[i] = written

        return self.side_effects

    def count_write_for_block(self, mblock):
        insn = mblock.head
        while insn:
            idx = self.side_effect_check(insn)
            if idx:
                yield idx
            insn = insn.next

    def side_effect_check(self, insn):
        if insn.is_like_move() and insn.d.t == hr.mop_l:
            # todo: block
            # print(insn.d.l.idx, insn.d.l.off // 8, insn._print())
            return insn.d.l.idx


class WriteOnceDetection:
    def __init__(self, mba, side_effects, lvar):
        self.mba = mba
        self.side_effects = side_effects
        self.visited = set()
        self.lvar = lvar
        self.count = 0

    def visit(self, block):
        if block in self.visited:
            return

        self.visited.add(block)

        if self.lvar in self.side_effects.get(block, []):
            self.count += 1
            if self.count > 1:
                return

        for idx in self.mba.get_mblock(block).succset:
            self.visit(idx)

    def check(self, block):
        self.visit(block)
        return self.count <= 1
