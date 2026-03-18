/* 简化的 EEVDF 测试 - 使用 kfunc 声明 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "kfuncs.h"

char LICENSE[] SEC("license") = "GPL";

/* 测试 bpf_eevdf_is_eligible - 最简单的 kfunc */
SEC("syscall")
int test_is_eligible(void)
{
	u64 vruntime = 100;
	u64 avg_vruntime = 200;

	/* 直接调用，不声明 - 让 BPF verifier 解析 */
	return bpf_eevdf_is_eligible(vruntime, avg_vruntime);
}
