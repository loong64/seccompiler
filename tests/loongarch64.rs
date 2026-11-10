// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

fn socket_filter(arch: TargetArch, socket_nr: i64) -> BpfProgram {
    let rule = SeccompRule::new(vec![SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Ne,
        libc::AF_UNIX as u64,
    )
    .unwrap()])
    .unwrap();
    SeccompFilter::new(
        BTreeMap::from([(socket_nr, vec![rule])]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .unwrap()
    .try_into()
    .unwrap()
}

// Evaluate the classic BPF instructions emitted for this rule against synthetic
// seccomp_data, so the LoongArch architecture guard is also exercised on x86.
fn evaluate(program: &BpfProgram, arch: u32, syscall: u32, family: u32) -> u32 {
    let mut pc = 0;
    let mut accumulator = 0;
    for _ in 0..program.len() {
        let instruction = &program[pc];
        match instruction.code {
            0x20 => {
                accumulator = match instruction.k {
                    0 => syscall,
                    4 => arch,
                    16 => family,
                    offset => panic!("unexpected seccomp_data offset: {offset}"),
                };
                pc += 1;
            }
            0x15 => {
                pc += 1 + usize::from(if accumulator == instruction.k {
                    instruction.jt
                } else {
                    instruction.jf
                });
            }
            0x05 => pc += 1 + instruction.k as usize,
            0x06 => return instruction.k,
            code => panic!("unexpected BPF instruction: {code:#x}"),
        }
    }
    panic!("filter did not return an action");
}

#[test]
fn loongarch64_filter_checks_architecture_and_preserves_network_restrictions() {
    let program = socket_filter(TargetArch::loongarch64, 198);
    let loongarch64 = 0xc000_0102;
    let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;

    assert_eq!(
        evaluate(&program, loongarch64, 198, libc::AF_INET as u32),
        denied
    );
    assert_eq!(
        evaluate(&program, loongarch64, 198, libc::AF_INET6 as u32),
        denied
    );
    assert_eq!(
        evaluate(&program, loongarch64, 198, libc::AF_UNIX as u32),
        libc::SECCOMP_RET_ALLOW
    );
    assert_eq!(
        evaluate(&program, loongarch64, 57, 0),
        libc::SECCOMP_RET_ALLOW
    );
    for wrong_arch in [0xc000_003e, 0xc000_00b7, 0xc000_00f3, 0x4000_0102] {
        assert_eq!(
            evaluate(&program, wrong_arch, 198, libc::AF_UNIX as u32),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }
}

#[test]
fn native_kernel_enforces_socket_filter() {
    // This runs against the real kernel on a native LoongArch machine, and
    // against the host architecture when validating the patch on x86/aarch64.
    std::thread::spawn(|| {
        let arch = TargetArch::try_from(std::env::consts::ARCH).unwrap();
        seccompiler::apply_filter(&socket_filter(arch, libc::SYS_socket)).unwrap();
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);
        unsafe { libc::close(fd) };
        assert_eq!(
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    })
    .join()
    .unwrap();
}
