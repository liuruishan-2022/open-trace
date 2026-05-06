use aya::programs::TracePoint;

pub fn load_sys_enter_open(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf.program_mut("sys_enter_open").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_open")?;
    Ok(())
}

pub fn load_io(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    load_sys_enter_open(ebpf)?;
    Ok(())
}
