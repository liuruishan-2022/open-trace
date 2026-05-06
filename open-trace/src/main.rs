use aya_log::EbpfLogger;
use log::debug;
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal,
};

pub mod loader;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/open-trace"
    )))?;
    let logger = EbpfLogger::init(&mut ebpf)?;
    let mut logger = AsyncFd::with_interest(logger, Interest::READABLE)?;
    tokio::task::spawn(async move {
        loop {
            let Ok(mut guard) = logger.readable_mut().await else {
                break;
            };
            guard.get_inner_mut().flush();
            guard.clear_ready();
        }
    });

    loader::load_ebpf(&mut ebpf)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
