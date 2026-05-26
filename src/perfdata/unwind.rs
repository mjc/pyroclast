#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerfX86_64Regs {
    pub ip: u64,
    pub sp: u64,
    pub bp: u64,
}

pub struct PerfStackReader<'a> {
    sp: u64,
    bytes: &'a [u8],
}

impl PerfX86_64Regs {
    /// Builds the minimal `x86_64` register set needed for stack unwinding from
    /// perf's ascending register-mask encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when the value slice does not match the number of set
    /// bits in `mask`.
    pub fn from_perf_masked_values(mask: u64, values: &[u64]) -> Result<Self, String> {
        if mask.count_ones() as usize != values.len() {
            return Err("perf register mask and value count differ".to_string());
        }

        let mut ip = None;
        let mut sp = None;
        let mut bp = None;
        let mut values = values.iter().copied();
        for register in 0..64 {
            if mask & (1 << register) == 0 {
                continue;
            }
            let value = values
                .next()
                .ok_or_else(|| "perf register value is missing".to_string())?;
            match register {
                6 => bp = Some(value),
                7 => sp = Some(value),
                8 => ip = Some(value),
                _ => {}
            }
        }

        Ok(Self {
            ip: ip.ok_or_else(|| "perf sample is missing x86_64 IP register".to_string())?,
            sp: sp.ok_or_else(|| "perf sample is missing x86_64 SP register".to_string())?,
            bp: bp.ok_or_else(|| "perf sample is missing x86_64 BP register".to_string())?,
        })
    }
}

impl<'a> PerfStackReader<'a> {
    #[must_use]
    pub fn new(sp: u64, bytes: &'a [u8]) -> Self {
        Self { sp, bytes }
    }

    #[must_use]
    pub fn read_u64(&self, address: u64) -> Option<u64> {
        let offset = usize::try_from(address.checked_sub(self.sp)?).ok()?;
        let bytes = self.bytes.get(offset..offset.checked_add(8)?)?;
        let bytes: [u8; 8] = bytes.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }
}
