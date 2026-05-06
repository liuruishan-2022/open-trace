use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::PerCpuArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[repr(C)]
pub struct FilenameBuf {
    pub buf: [u8; 256],
}

#[map]
static FILENAME_BUF: PerCpuArray<FilenameBuf> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    match try_sys_enter_open(ctx) {
        Ok(ret) => ret as u32,
        Err(_) => 1 as u32,
    }
}

///
/// name: sys_enter_open
/// ID: 708
/// format:
///         field:unsigned short common_type;       offset:0;       size:2; signed:0;
///         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
///         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
///         field:int common_pid;   offset:4;       size:4; signed:1;
///
///         field:int __syscall_nr; offset:8;       size:4; signed:1;
///         field:const char * filename;    offset:16;      size:8; signed:0;
///         field:int flags;        offset:24;      size:8; signed:0;
///         field:umode_t mode;     offset:32;      size:8; signed:0;
///
/// 注意：filename 是一个指针（指向用户空间），不是内联的字符串数组
/// 需要先读取指针值，然后从用户空间读取字符串内容
///
fn try_sys_enter_open(ctx: TracePointContext) -> Result<c_long, c_long> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let filename_ptr: *const u8 = unsafe { ctx.read_at(16).map_err(|err| err as c_long)? };
    let filename_buf = unsafe {
        let ptr = FILENAME_BUF.get_ptr_mut(0).ok_or(1 as c_long)?;
        &mut *ptr
    };
    let filename = unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf.buf)
            .map_err(|err| err as c_long)?
    };
    let filename = unsafe { core::str::from_utf8_unchecked(filename) };

    info!(
        &ctx,
        "sys_enter_open pid={} tid={} filename={}",
        pid,
        tid,
        filename
    );

    Ok(0)
}
