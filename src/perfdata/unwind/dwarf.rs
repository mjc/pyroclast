use std::ops::Range;

use gimli::{
    BaseAddresses, CallFrameInstruction, CfaRule, CieOrFde, DebugFrame, EhFrame, Encoding,
    EndianSlice, Expression, FrameDescriptionEntry, LittleEndian, Operation, Reader, Register,
    RegisterRule, UnwindContext, UnwindSection, UnwindTableRow,
};

use super::{
    ExplicitModuleSectionInfo, ModuleAddresses, ModuleBytes, PerfX86_64Regs, Reg, UnwindRegsX86_64,
};

type Bytes<'a> = EndianSlice<'a, LittleEndian>;

pub(super) struct Cache {
    context: UnwindContext<usize>,
    expression_offsets: Vec<usize>,
}

impl Cache {
    pub(super) fn new() -> Self {
        Self {
            context: UnwindContext::new(),
            expression_offsets: Vec::with_capacity(4096),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Registers {
    values: [u64; 17],
    valid: u32,
}

impl Registers {
    pub(super) fn new(regs: PerfX86_64Regs) -> Self {
        let mut values = [0; 17];
        for (value, recorded) in values.iter_mut().zip(regs.registers) {
            *value = recorded;
        }
        values[6] = regs.bp;
        values[7] = regs.sp;
        values[16] = regs.ip;
        Self {
            values,
            valid: (1 << 17) - 1,
        }
    }

    fn empty() -> Self {
        Self {
            values: [0; 17],
            valid: 0,
        }
    }

    fn set(&mut self, number: usize, value: Option<u64>) {
        if let Some(value) = value {
            self.values[number] = value;
            self.valid |= 1 << number;
        } else {
            self.values[number] = 0;
            self.valid &= !(1 << number);
        }
    }

    fn get(self, register: Register) -> Option<u64> {
        let number = usize::from(register.0);
        self.values
            .get(number)
            .copied()
            .filter(|_| self.valid & (1 << number) != 0)
    }

    pub(super) fn pc(self) -> Option<u64> {
        self.get(Register(16))
    }

    pub(super) fn framehop_regs(self) -> UnwindRegsX86_64 {
        let regs = PerfX86_64Regs {
            ip: self.pc().unwrap_or(0),
            sp: self.get(Register(7)).unwrap_or(0),
            bp: self.get(Register(6)).unwrap_or(0),
            registers: std::array::from_fn(|index| self.values[index]),
        };
        regs.to_framehop_regs()
    }

    pub(super) fn from_framehop(regs: UnwindRegsX86_64) -> Self {
        let order = [
            Reg::RAX,
            Reg::RDX,
            Reg::RCX,
            Reg::RBX,
            Reg::RSI,
            Reg::RDI,
            Reg::RBP,
            Reg::RSP,
            Reg::R8,
            Reg::R9,
            Reg::R10,
            Reg::R11,
            Reg::R12,
            Reg::R13,
            Reg::R14,
            Reg::R15,
        ];
        let mut caller = Self::empty();
        for (number, register) in order.into_iter().enumerate() {
            caller.set(number, Some(regs.get(register)));
        }
        caller.set(16, Some(regs.ip()));
        caller
    }

    pub(super) fn frame_pointer_step(self, read: &mut impl FnMut(u64) -> Result<u64, ()>) -> Step {
        // elfutils backends/x86_64_unwind.c:48-91: missing old SP is zero,
        // missing previous FP is nonfatal, and only these three regs are set.
        let Some(fp) = self.get(Register(6)).filter(|fp| *fp != 0) else {
            return Step::Stop;
        };
        let previous = read(fp).unwrap_or(0);
        let Ok(pc) = read(fp.wrapping_add(8)) else {
            return Step::Stop;
        };
        let sp = fp.wrapping_add(16);
        if self.get(Register(7)).unwrap_or(0) >= sp || pc == 0 {
            return Step::Stop;
        }
        let mut caller = Self::empty();
        caller.set(6, Some(previous));
        caller.set(7, Some(sp));
        caller.set(16, Some(pc));
        Step::Caller(caller, false)
    }
}

pub(super) enum Step {
    NoRow,
    Stop,
    Caller(Registers, bool),
}

#[derive(Clone)]
pub(super) struct Module {
    addresses: ModuleAddresses,
    bases: BaseAddresses,
    eh: Option<Section>,
    debug: Option<Section>,
}

#[derive(Clone)]
struct Section {
    bytes: ModuleBytes,
    index: Vec<Entry>,
}

#[derive(Clone)]
struct Entry {
    start: u64,
    end: u64,
    offset: usize,
    max_end: u64,
    undefined_cfa: Vec<Range<u64>>,
}

impl Module {
    pub(super) fn new(
        sections: &ExplicitModuleSectionInfo<ModuleBytes>,
        addresses: ModuleAddresses,
        bases: BaseAddresses,
    ) -> Self {
        let eh = sections
            .eh_frame
            .as_ref()
            .map(|bytes| Section::new(bytes.clone(), &EhFrame::new(bytes, LittleEndian), &bases));
        let debug = sections.debug_frame.as_ref().map(|bytes| {
            let mut section = DebugFrame::new(bytes, LittleEndian);
            section.set_address_size(8);
            Section::new(bytes.clone(), &section, &bases)
        });
        Self {
            addresses,
            bases,
            eh,
            debug,
        }
    }

    pub(super) fn step(
        &self,
        address: u64,
        regs: Registers,
        cache: &mut Cache,
        read: &mut impl FnMut(u64) -> Result<u64, ()>,
    ) -> Step {
        let linked = address
            .wrapping_sub(self.addresses.base_avma)
            .wrapping_add(self.addresses.base_svma);
        if let Some(data) = &self.eh {
            let section = EhFrame::new(&data.bytes, LittleEndian);
            let step = self.section_step((data, &section), linked, regs, cache, read);
            if !matches!(step, Step::NoRow) {
                return step;
            }
        }
        if let Some(data) = &self.debug {
            let mut section = DebugFrame::new(&data.bytes, LittleEndian);
            section.set_address_size(8);
            return self.section_step((data, &section), linked, regs, cache, read);
        }
        Step::NoRow
    }

    fn section_step<'a>(
        &self,
        (data, section): (&Section, &impl UnwindSection<Bytes<'a>>),
        address: u64,
        regs: Registers,
        cache: &mut Cache,
        read: &mut impl FnMut(u64) -> Result<u64, ()>,
    ) -> Step {
        let Some(entry) = data.entry(address) else {
            return Step::NoRow;
        };
        let Ok(fde) = section.fde_from_offset(
            &self.bases,
            entry.offset.into(),
            UnwindSection::cie_from_offset,
        ) else {
            return Step::NoRow;
        };
        let Ok(row) =
            fde.unwind_info_for_address(section, &self.bases, &mut cache.context, address)
        else {
            return Step::NoRow;
        };
        // frame_unwind.c:529-675: after row decoding, recover registers
        // independently into a fresh successor. No evaluation error tries EBL.
        let evaluator = Evaluator {
            regs,
            cfa: None,
            encoding: fde.cie().encoding(),
            addresses: self.addresses,
        };
        let undefined = entry
            .undefined_cfa
            .partition_point(|range| range.end <= address);
        let cfa = if entry
            .undefined_cfa
            .get(undefined)
            .is_some_and(|range| range.contains(&address))
        {
            None
        } else {
            match row.cfa() {
                CfaRule::RegisterAndOffset { register, offset } => regs
                    .get(*register)
                    .map(|value| value.wrapping_add_signed(*offset)),
                CfaRule::Expression(expr) => expr.get(section).ok().and_then(|expr| {
                    evaluator.expression(
                        expr,
                        ExpressionKind::Cfa,
                        read,
                        &mut cache.expression_offsets,
                    )
                }),
            }
        };
        let evaluator = Evaluator { cfa, ..evaluator };
        let mut caller = Registers::empty();
        for number in 0..17 {
            let register = Register(u16::try_from(number).expect("17 registers"));
            caller.set(
                number,
                evaluator.register(section, row, register, read, &mut cache.expression_offsets),
            );
        }
        let Some(pc) = caller
            .get(fde.cie().return_address_register())
            .filter(|pc| *pc != 0)
        else {
            return Step::Stop;
        };
        caller.set(16, Some(pc));
        Step::Caller(caller, fde.is_signal_trampoline())
    }
}

impl Section {
    fn new<'a>(
        bytes: ModuleBytes,
        section: &impl UnwindSection<Bytes<'a>>,
        bases: &BaseAddresses,
    ) -> Self {
        let mut entries = section.entries(bases);
        let mut index = Vec::new();
        while let Ok(Some(entry)) = entries.next() {
            let CieOrFde::Fde(partial) = entry else {
                continue;
            };
            let Ok(fde) = partial.parse(UnwindSection::cie_from_offset) else {
                continue;
            };
            index.push(Entry {
                start: fde.initial_address(),
                end: fde.end_address(),
                offset: fde.offset(),
                max_end: 0,
                undefined_cfa: undefined_cfa_ranges(&fde, section, bases),
            });
        }
        index.sort_unstable_by_key(|entry| (entry.start, entry.offset));
        let mut max_end = 0;
        for entry in &mut index {
            max_end = max_end.max(entry.end);
            entry.max_end = max_end;
        }
        Self { bytes, index }
    }

    fn entry(&self, address: u64) -> Option<&Entry> {
        let end = self.index.partition_point(|entry| entry.start <= address);
        for entry in self.index[..end].iter().rev() {
            if entry.max_end <= address {
                break;
            }
            if address < entry.end {
                return Some(entry);
            }
        }
        None
    }
}

#[derive(Default)]
struct CfaDefinition {
    defined: bool,
    saved: Vec<bool>,
}

impl CfaDefinition {
    fn apply(&mut self, instruction: &CallFrameInstruction<usize>) {
        match instruction {
            CallFrameInstruction::DefCfa { .. }
            | CallFrameInstruction::DefCfaSf { .. }
            | CallFrameInstruction::DefCfaExpression { .. } => self.defined = true,
            CallFrameInstruction::RememberState => self.saved.push(self.defined),
            CallFrameInstruction::RestoreState => {
                if let Some(defined) = self.saved.pop() {
                    self.defined = defined;
                }
            }
            _ => {}
        }
    }
}

fn undefined_cfa_ranges<'a>(
    fde: &FrameDescriptionEntry<Bytes<'a>>,
    section: &impl UnwindSection<Bytes<'a>>,
    bases: &BaseAddresses,
) -> Vec<Range<u64>> {
    // Gimli's default CFA is indistinguishable from explicit RAX+0. Preserve
    // only its missing validity bit; Gimli still decodes/evaluates every rule.
    // libdw/cfi.c:482-522 and dwarf_frame_cfa.c:46-50 start CFA undefined.
    let mut state = CfaDefinition::default();
    let mut initial = fde.cie().instructions(section, bases);
    while let Ok(Some(instruction)) = initial.next() {
        state.apply(&instruction);
    }
    if state.defined && state.saved.iter().all(|defined| *defined) {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut address = fde.initial_address();
    let mut undefined_start = (!state.defined).then_some(address);
    let mut instructions = fde.instructions(section, bases);
    while let Ok(Some(instruction)) = instructions.next() {
        match instruction {
            CallFrameInstruction::SetLoc { address: next } => {
                if next < address {
                    break;
                }
                address = next;
            }
            CallFrameInstruction::AdvanceLoc { delta } => {
                let delta = u64::from(delta).wrapping_mul(fde.cie().code_alignment_factor());
                let Some(next) = address.checked_add(delta) else {
                    break;
                };
                address = next;
            }
            _ => state.apply(&instruction),
        }
        if state.defined {
            if let Some(start) = undefined_start.take()
                && start < address
            {
                ranges.push(start..address);
            }
        } else {
            undefined_start.get_or_insert(address);
        }
    }
    if let Some(start) = undefined_start
        && start < fde.end_address()
    {
        ranges.push(start..fde.end_address());
    }
    ranges
}

struct Evaluator {
    regs: Registers,
    cfa: Option<u64>,
    encoding: Encoding,
    addresses: ModuleAddresses,
}

impl Evaluator {
    fn register<'a>(
        &self,
        section: &impl UnwindSection<Bytes<'a>>,
        row: &UnwindTableRow<usize>,
        register: Register,
        read: &mut impl FnMut(u64) -> Result<u64, ()>,
        offsets: &mut Vec<usize>,
    ) -> Option<u64> {
        // Match the actual elfutils 0.195 x86_64_cfi.c:39-61 defaults,
        // including DWARF register 0 (despite its source comment saying rbx).
        let rule = row.register(register).unwrap_or(match register.0 {
            0 | 6 | 12..=16 => RegisterRule::SameValue,
            7 => RegisterRule::ValOffset(0),
            _ => RegisterRule::Undefined,
        });
        match rule {
            RegisterRule::Undefined | RegisterRule::Architectural => None,
            RegisterRule::SameValue => self.regs.get(register),
            RegisterRule::Offset(offset) => read(self.cfa?.wrapping_add_signed(offset)).ok(),
            RegisterRule::ValOffset(offset) => Some(self.cfa?.wrapping_add_signed(offset)),
            RegisterRule::Register(register) => self.regs.get(register),
            RegisterRule::Expression(expr) => self.expression(
                expr.get(section).ok()?,
                ExpressionKind::Location,
                read,
                offsets,
            ),
            RegisterRule::ValExpression(expr) => self.expression(
                expr.get(section).ok()?,
                ExpressionKind::Value,
                read,
                offsets,
            ),
            RegisterRule::Constant(value) => Some(value),
        }
    }

    fn expression(
        &self,
        expression: Expression<Bytes<'_>>,
        kind: ExpressionKind,
        read: &mut impl FnMut(u64) -> Result<u64, ()>,
        offsets: &mut Vec<usize>,
    ) -> Option<u64> {
        let bytes = expression.0;
        if bytes.is_empty() {
            return None;
        }
        // Native branches search decoded instruction offsets, not arbitrary
        // byte offsets. Reuse the scratch allocation across all expressions.
        offsets.clear();
        let mut input = bytes;
        while !input.is_empty() {
            offsets.push(bytes.len() - input.len());
            Operation::parse(&mut input, self.encoding).ok()?;
        }
        let mut stack = ExpressionStack::new();
        let mut is_location = kind != ExpressionKind::Cfa;
        let mut steps = usize::from(is_location);
        if is_location {
            // dwarf_getlocation.c:313-321 synthesizes this CFA prefix.
            stack.push(self.cfa?)?;
        }
        input = bytes;
        while !input.is_empty() {
            steps += 1;
            if steps > 4096 {
                return None;
            }
            let operation = Operation::parse(&mut input, self.encoding).ok()?;
            let branch = match operation {
                Operation::Skip { target } => Some(target),
                Operation::Bra { target } => (stack.pop()? != 0).then_some(target),
                _ => {
                    self.expression_operation(&operation, &mut stack, &mut is_location, read)?;
                    None
                }
            };
            if let Some(target) = branch {
                let destination =
                    (bytes.len() - input.len()).checked_add_signed(isize::from(target))?;
                // ValExpression appends a synthetic stack_value at byte end.
                if offsets.binary_search(&destination).is_err()
                    && !(kind == ExpressionKind::Value && destination == bytes.len())
                {
                    return None;
                }
                input = bytes;
                input.skip(destination).ok()?;
            }
        }
        if kind == ExpressionKind::Value {
            steps += 1;
            if steps > 4096 {
                return None;
            }
            is_location = false;
        }
        let value = stack.pop()?;
        if is_location {
            read(value).ok()
        } else {
            Some(value)
        }
    }

    fn expression_operation(
        &self,
        operation: &Operation<Bytes<'_>>,
        stack: &mut ExpressionStack,
        is_location: &mut bool,
        read: &mut impl FnMut(u64) -> Result<u64, ()>,
    ) -> Option<()> {
        // frame_unwind.c:152-473 is a CFI stack machine, not a DWARF location
        // description: regN pushes a value; stack_value changes a continuing
        // dereference flag. Gimli still owns all bytecode decoding.
        match *operation {
            Operation::UnsignedConstant { value } => stack.push(value),
            Operation::SignedConstant { value } => stack.push(value.cast_unsigned()),
            Operation::Register { register } => stack.push(self.regs.get(register)?),
            Operation::RegisterOffset {
                register,
                offset,
                base_type,
            } if base_type.0 == 0 => {
                stack.push(self.regs.get(register)?.wrapping_add_signed(offset))
            }
            Operation::Address { address } => stack.push(
                address
                    .wrapping_sub(self.addresses.base_svma)
                    .wrapping_add(self.addresses.base_avma),
            ),
            Operation::Deref {
                base_type,
                size,
                space: false,
            } if base_type.0 == 0 && size <= 8 => {
                // Native memory_read reads a full word, even for deref_size.
                let value = read(stack.pop()?).ok()?;
                stack.push(if size == 8 {
                    value
                } else {
                    value & ((1_u64 << (u32::from(size) * 8)) - 1)
                })
            }
            Operation::Drop => stack.pop().map(|_| ()),
            Operation::Pick { index } => {
                let value = *stack
                    .values
                    .get(stack.len.checked_sub(usize::from(index) + 1)?)?;
                stack.push(value)
            }
            Operation::Swap => {
                stack
                    .values
                    .get_mut(stack.len.checked_sub(2)?..stack.len)?
                    .swap(0, 1);
                Some(())
            }
            Operation::Rot => {
                stack
                    .values
                    .get_mut(stack.len.checked_sub(3)?..stack.len)?
                    .rotate_right(1);
                Some(())
            }
            Operation::CallFrameCFA => {
                stack.push(self.cfa?)?;
                *is_location = true;
                Some(())
            }
            Operation::StackValue => {
                *is_location = false;
                Some(())
            }
            Operation::Nop => Some(()),
            _ => stack.arithmetic(operation),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ExpressionKind {
    Cfa,
    Location,
    Value,
}

struct ExpressionStack {
    values: [u64; 256],
    len: usize,
}

impl ExpressionStack {
    fn new() -> Self {
        Self {
            values: [0; 256],
            len: 0,
        }
    }

    fn push(&mut self, value: u64) -> Option<()> {
        *self.values.get_mut(self.len)? = value;
        self.len += 1;
        Some(())
    }

    fn pop(&mut self) -> Option<u64> {
        self.len = self.len.checked_sub(1)?;
        Some(self.values[self.len])
    }

    fn arithmetic(&mut self, operation: &Operation<Bytes<'_>>) -> Option<()> {
        let right = self.pop()?;
        let unary = match operation {
            Operation::Abs => Some(right.cast_signed().wrapping_abs().cast_unsigned()),
            Operation::Neg => Some(right.wrapping_neg()),
            Operation::Not => Some(!right),
            Operation::PlusConstant { value } => Some(right.wrapping_add(*value)),
            _ => None,
        };
        if let Some(value) = unary {
            return self.push(value);
        }
        let left = self.pop()?;
        let value = match operation {
            Operation::And => left & right,
            Operation::Div => left
                .cast_signed()
                .checked_div(right.cast_signed())?
                .cast_unsigned(),
            Operation::Minus => left.wrapping_sub(right),
            Operation::Mod => left.checked_rem(right)?,
            Operation::Mul => left.wrapping_mul(right),
            Operation::Or => left | right,
            Operation::Plus => left.wrapping_add(right),
            Operation::Shl => left.wrapping_shl(u32::try_from(right & 63).ok()?),
            Operation::Shr => left.wrapping_shr(u32::try_from(right & 63).ok()?),
            Operation::Shra => left
                .cast_signed()
                .wrapping_shr(u32::try_from(right & 63).ok()?)
                .cast_unsigned(),
            Operation::Xor => left ^ right,
            Operation::Eq => u64::from(left == right),
            Operation::Ge => u64::from(left.cast_signed() >= right.cast_signed()),
            Operation::Gt => u64::from(left.cast_signed() > right.cast_signed()),
            Operation::Le => u64::from(left.cast_signed() <= right.cast_signed()),
            Operation::Lt => u64::from(left.cast_signed() < right.cast_signed()),
            Operation::Ne => u64::from(left != right),
            _ => return None,
        };
        self.push(value)
    }
}
