#include <linux/module.h>
#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <asm/vmx.h>
#include <asm/msr-index.h>
#include "protovirt.h"


static __always_inline void save_volatile_regs(void)
{
	asm volatile(
		"push %%r15\n"
		"push %%r14\n"
		"push %%r13\n"
		"push %%r12\n"
		"push %%r11\n"
		"push %%r10\n"
		"push %%r9\n"
		"push %%r8\n"
		"push %%rdi\n"
		"push %%rsi\n"
		"push %%rbp\n"
		"push %%rbp\n" // placeholder for rsp
		"push %%rbx\n"
		"push %%rdx\n"
		"push %%rcx\n"
		"push %%rax\n"
		:
	);
}

static __always_inline void restore_volatile_regs(void)
{
	asm volatile(
		"pop %%rax\n"
		"pop %%rcx\n"
		"pop %%rdx\n"
		"pop %%rbx\n"
		"pop %%rbp\n" // placeholder for rsp
		"pop %%rbp\n"
		"pop %%rsi\n"
		"pop %%rdi\n"
		"pop %%r8\n"
		"pop %%r9\n"
		"pop %%r10\n"
		"pop %%r11\n"
		"pop %%r12\n"
		"pop %%r13\n"
		"pop %%r14\n"
		"pop %%r15\n"
		:
	);
}

static __always_inline void print_regs(void)
{
	uint64_t rax, rcx, rdx, rbx, rbp, rsp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15;

	asm volatile(
		"mov %%rax, %[rax]\n"
		"mov %%rcx, %[rcx]\n"
		"mov %%rdx, %[rdx]\n"
		"mov %%rbx, %[rbx]\n"
		"mov %%rbp, %[rbp]\n"
		"mov %%rsp, %[rsp]\n"
		"mov %%rsi, %[rsi]\n"
		"mov %%rdi, %[rdi]\n"
		"mov %%r8, %[r8]\n"
		"mov %%r9, %[r9]\n"
		"mov %%r10, %[r10]\n"
		"mov %%r11, %[r11]\n"
		"mov %%r12, %[r12]\n"
		"mov %%r13, %[r13]\n"
		"mov %%r14, %[r14]\n"
		"mov %%r15, %[r15]\n"
		: [rax] "=m"(rax),
		  [rcx] "=m"(rcx),
		  [rdx] "=m"(rdx),
		  [rbx] "=m"(rbx),
		  [rbp] "=m"(rbp),
		  [rsp] "=m"(rsp),
		  [rsi] "=m"(rsi),
		  [rdi] "=m"(rdi),
		  [r8] "=m"(r8),
		  [r9] "=m"(r9),
		  [r10] "=m"(r10),
		  [r11] "=m"(r11),
		  [r12] "=m"(r12),
		  [r13] "=m"(r13),
		  [r14] "=m"(r14),
		  [r15] "=m"(r15)
	);
	save_volatile_regs();
	printk(KERN_INFO "rax: 0x%016llX, rcx: 0x%016llX, rdx: 0x%016llX, rbx: 0x%016llX\n", rax, rcx, rdx, rbx);
	printk(KERN_INFO "rbp: 0x%016llX, rsp: 0x%016llX, rsi: 0x%016llX, rdi: 0x%016llX\n", rbp, rsp, rsi, rdi);
	printk(KERN_INFO "r8: 0x%016llX, r9: 0x%016llX, r10: 0x%016llX, r11: 0x%016llX\n", r8, r9, r10, r11);
	printk(KERN_INFO "r12: 0x%016llX, r13: 0x%016llX, r14: 0x%016llX, r15: 0x%016llX\n", r12, r13, r14, r15);
	restore_volatile_regs();
}

/////////the above is helper code////////////////

// CH 23.6, Vol 3
// Checking the support of VMX
bool vmxSupport(void)
{
    int getVmxSupport, vmxBit;
    __asm__("mov $1, %rax");
    __asm__("cpuid");
    __asm__("mov %%ecx , %0\n\t":"=r" (getVmxSupport));
    vmxBit = (getVmxSupport >> 5) & 1;
    if (vmxBit == 1){
        return true;
    }
    return false;
}

// Enter in VMX mode
bool getVmxOperation(void) {
	uint64_t cr4;
	uint64_t cr0;
    uint64_t feature_control;
	uint64_t required;
	long int vmxon_phy_region = 0;
	uint32_t revision_identifier;
	uint64_t msr_ia32_vmx_basic;

    /*CH 23.7, Vol 3
	 * Configure IA32_FEATURE_CONTROL MSR to allow VMXON:
	 *  Bit 0: Lock bit. If clear, VMXON causes a #GP.
	 *  Bit 2: Enables VMXON outside of SMX operation. If clear, VMXON
	 *    outside of SMX causes a #GP.
	 */
	feature_control = __rdmsr(MSR_IA32_FEATURE_CONTROL);
	required = FEATURE_CONTROL_LOCKED; //this bit must be set before execute vmxon, and msr cannot be write after set.
	required |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
	required |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX; //SMX feature, just enable it.maybe useful
	if ((feature_control & required) != required) {
		printk(KERN_INFO "write MSR_IA32_FEATURE_CONTROL register\n");
		__wrmsr(MSR_IA32_FEATURE_CONTROL, feature_control | required,0); //this is a 64bit register
	}

	/* In 23.8 chapter, more details in A.7 and A.8, for no reason, just like a game.
	 * Ensure bits in CR0 and CR4 are valid in VMX operation:
	 * - Bit X is 1 in _FIXED0: bit X is fixed to 1 in CRx.
	 * - Bit X is 0 in _FIXED1: bit X is fixed to 0 in CRx.
	 */
	__asm__ __volatile__("mov %%cr0, %0" : "=r"(cr0) : : "memory");
	cr0 &= __rdmsr(MSR_IA32_VMX_CR0_FIXED1);
	cr0 |= __rdmsr(MSR_IA32_VMX_CR0_FIXED0);
	__asm__ __volatile__("mov %0, %%cr0" : : "r"(cr0) : "memory");

	__asm__ __volatile__("mov %%cr4, %0" : "=r"(cr4) : : "memory");
	cr4 &= __rdmsr(MSR_IA32_VMX_CR4_FIXED1);
	cr4 |= __rdmsr(MSR_IA32_VMX_CR4_FIXED0);
	cr4 |= X86_CR4_VMXE;  // setting CR4.VMXE[bit 13] = 1,
	__asm__ __volatile__("mov %0, %%cr4" : : "r"(cr4) : "memory");

    msr_ia32_vmx_basic = __rdmsr(MSR_IA32_VMX_BASIC);
	revision_identifier = msr_ia32_vmx_basic; //appendix A.1
	MYPAGE_SIZE  = (msr_ia32_vmx_basic >> 32 & 0x1FFF);
	if (MYPAGE_SIZE != 4096) {
		printk(KERN_WARNING "Get page size [%d]!=4096 from msr_ia32_vmx_basic.\n", MYPAGE_SIZE);
	}
	// allocating 4kib((4096 bytes) of memory for vmxon region
	g_vmxonRegion = kzalloc(MYPAGE_SIZE,GFP_KERNEL); //this is global
	// Same with vmcs in terms of form, but not the same meaning.
	// https://zhuanlan.zhihu.com/p/49400702?msclkid=271190cabe2a11eca695cb5d2f964c08
    if(g_vmxonRegion==NULL){
		printk(KERN_INFO "Error allocating vmxon region\n");
      	return false;
   	}
	vmxon_phy_region = __pa(g_vmxonRegion);
	*(uint32_t *)g_vmxonRegion = revision_identifier; //24.11.5
	if (_vmxon(vmxon_phy_region))
		return false;
	return true;
}

// CH 24.2, Vol 3
// allocating VMCS region
bool vmcsOperations(void) {
	long int vmcsPhyRegion = 0;
	if (allocVmcsRegion()){
		vmcsPhyRegion = __pa(g_vmcsRegion);
		*(uint32_t *)g_vmcsRegion = __rdmsr(MSR_IA32_VMX_BASIC);
	}
	else {
		return false;
	}

    if (vmclear(vmcsPhyRegion))
		return false;
    
	//making the vmcs active and current
	if (vmptrld(vmcsPhyRegion))
		return false;
	return true;
}

/*
 * Initialize the control fields to the most basic settings possible.
 */
static inline void init_vmcs_control_fields(void)
{
	vmwrite(VIRTUAL_PROCESSOR_ID, 0);
	vmwrite(POSTED_INTR_NV, 0);

	vmwrite(PIN_BASED_VM_EXEC_CONTROL, __rdmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS));
    // the MSR was not set from the following code, so maybe the following readmsr bitmap may be not neccessary.
	// printk(KERN_INFO "=====PROCBASED=====: 0x%016llX", __rdmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS)&CPU_BASED_USE_MSR_BITMAPS);
	if (!vmwrite(SECONDARY_VM_EXEC_CONTROL, 0))
		vmwrite(CPU_BASED_VM_EXEC_CONTROL,
			__rdmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS) | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
	else
		vmwrite(CPU_BASED_VM_EXEC_CONTROL, __rdmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS));
	vmwrite(EXCEPTION_BITMAP, 0);
	vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, -1); /* Never match */
	vmwrite(CR3_TARGET_COUNT, 0);
	vmwrite(VM_EXIT_CONTROLS, __rdmsr(MSR_IA32_VMX_EXIT_CTLS) |
		VM_EXIT_HOST_ADDR_SPACE_SIZE);	  /* 64-bit host */
	vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	vmwrite(VM_ENTRY_CONTROLS, __rdmsr(MSR_IA32_VMX_ENTRY_CTLS) |
		VM_ENTRY_IA32E_MODE);		  /* 64-bit guest */
	vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
	vmwrite(TPR_THRESHOLD, 0);

	vmwrite(CR0_GUEST_HOST_MASK, 0);
	vmwrite(CR4_GUEST_HOST_MASK, 0);
	vmwrite(CR0_READ_SHADOW, get_cr0());
	vmwrite(CR4_READ_SHADOW, get_cr4());

	// vmwrite(MSR_BITMAP, vmx->msr_gpa);
	// this is useful for shadow mode, so maybe it is not necessary here two.
	// vmwrite(VMREAD_BITMAP, vmx->vmread_gpa);
	// vmwrite(VMWRITE_BITMAP, vmx->vmwrite_gpa);
}

static inline void init_vmcs_host_state(void)
{
	uint32_t exit_controls = vmreadz(VM_EXIT_CONTROLS);

	//HOST_RSP and HOST_RIP not set here, and it will be set in the vmlauch.
	vmwrite(HOST_ES_SELECTOR, get_es1());
	vmwrite(HOST_CS_SELECTOR, get_cs1());
	vmwrite(HOST_SS_SELECTOR, get_ss1());
	vmwrite(HOST_DS_SELECTOR, get_ds1());
	vmwrite(HOST_FS_SELECTOR, get_fs1());
	vmwrite(HOST_GS_SELECTOR, get_gs1());
	vmwrite(HOST_TR_SELECTOR, get_tr1());

	if (exit_controls & VM_EXIT_LOAD_IA32_PAT)
		vmwrite(HOST_IA32_PAT, __rdmsr(MSR_IA32_CR_PAT));
	if (exit_controls & VM_EXIT_LOAD_IA32_EFER)
		vmwrite(HOST_IA32_EFER, __rdmsr(MSR_EFER));
	if (exit_controls & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL)
		vmwrite(HOST_IA32_PERF_GLOBAL_CTRL,
			__rdmsr(MSR_CORE_PERF_GLOBAL_CTRL));
    // S_CET,INTERRUPT_SSP_TABLE_ADDR,PKRS](vol 24.5) are NOT set here, but it doesn't mind, because it is optional.

	vmwrite(HOST_IA32_SYSENTER_CS, __rdmsr(MSR_IA32_SYSENTER_CS));

	vmwrite(HOST_CR0, get_cr0());
	vmwrite(HOST_CR3, get_cr3());
	vmwrite(HOST_CR4, get_cr4());
	vmwrite(HOST_FS_BASE, __rdmsr(MSR_FS_BASE));
	vmwrite(HOST_GS_BASE, __rdmsr(MSR_GS_BASE));
	vmwrite(HOST_TR_BASE,
		get_desc64_base((struct desc64 *)(get_gdt_base1() + get_tr1())));
	vmwrite(HOST_GDTR_BASE, get_gdt_base1());
	vmwrite(HOST_IDTR_BASE, get_idt_base1());
	vmwrite(HOST_IA32_SYSENTER_ESP, __rdmsr(MSR_IA32_SYSENTER_ESP));
	vmwrite(HOST_IA32_SYSENTER_EIP, __rdmsr(MSR_IA32_SYSENTER_EIP));
}

/*
 * Initialize the guest state fields essentially as a clone of
 * the host state fields. Some host state fields have fixed
 * values, and we set the corresponding guest state fields accordingly.
 */
static inline void init_vmcs_guest_state(void *rip, void *rsp)
{
	vmwrite(GUEST_ES_SELECTOR, vmreadz(HOST_ES_SELECTOR));
	vmwrite(GUEST_CS_SELECTOR, vmreadz(HOST_CS_SELECTOR));
	vmwrite(GUEST_SS_SELECTOR, vmreadz(HOST_SS_SELECTOR));
	vmwrite(GUEST_DS_SELECTOR, vmreadz(HOST_DS_SELECTOR));
	vmwrite(GUEST_FS_SELECTOR, vmreadz(HOST_FS_SELECTOR));
	vmwrite(GUEST_GS_SELECTOR, vmreadz(HOST_GS_SELECTOR));
	vmwrite(GUEST_LDTR_SELECTOR, 0);
	vmwrite(GUEST_TR_SELECTOR, vmreadz(HOST_TR_SELECTOR));
	vmwrite(GUEST_INTR_STATUS, 0);
	vmwrite(GUEST_PML_INDEX, 0);

	vmwrite(VMCS_LINK_POINTER, -1ll);
	vmwrite(GUEST_IA32_DEBUGCTL, 0);
	vmwrite(GUEST_IA32_PAT, vmreadz(HOST_IA32_PAT));
	vmwrite(GUEST_IA32_EFER, vmreadz(HOST_IA32_EFER));
	vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL,
		vmreadz(HOST_IA32_PERF_GLOBAL_CTRL));

	vmwrite(GUEST_ES_LIMIT, -1);
	vmwrite(GUEST_CS_LIMIT, -1);
	vmwrite(GUEST_SS_LIMIT, -1);
	vmwrite(GUEST_DS_LIMIT, -1);
	vmwrite(GUEST_FS_LIMIT, -1);
	vmwrite(GUEST_GS_LIMIT, -1);
	vmwrite(GUEST_LDTR_LIMIT, -1);
	vmwrite(GUEST_TR_LIMIT, 0x67);
	vmwrite(GUEST_GDTR_LIMIT, 0xffff);
	vmwrite(GUEST_IDTR_LIMIT, 0xffff);
	vmwrite(GUEST_ES_AR_BYTES,
		vmreadz(GUEST_ES_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_CS_AR_BYTES, 0xa09b);
	vmwrite(GUEST_SS_AR_BYTES, 0xc093);
	vmwrite(GUEST_DS_AR_BYTES,
		vmreadz(GUEST_DS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_FS_AR_BYTES,
		vmreadz(GUEST_FS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_GS_AR_BYTES,
		vmreadz(GUEST_GS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_LDTR_AR_BYTES, 0x10000);
	vmwrite(GUEST_TR_AR_BYTES, 0x8b);
	vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmwrite(GUEST_ACTIVITY_STATE, 0);
	vmwrite(GUEST_SYSENTER_CS, vmreadz(HOST_IA32_SYSENTER_CS));
	vmwrite(VMX_PREEMPTION_TIMER_VALUE, 0);

	vmwrite(GUEST_CR0, vmreadz(HOST_CR0));
	vmwrite(GUEST_CR3, vmreadz(HOST_CR3));
	vmwrite(GUEST_CR4, vmreadz(HOST_CR4));
	vmwrite(GUEST_ES_BASE, 0); //according to manual, it has only 32bit
	vmwrite(GUEST_CS_BASE, 0);
	vmwrite(GUEST_SS_BASE, 0);
	vmwrite(GUEST_DS_BASE, 0);
	vmwrite(GUEST_FS_BASE, vmreadz(HOST_FS_BASE));
	vmwrite(GUEST_GS_BASE, vmreadz(HOST_GS_BASE));
	vmwrite(GUEST_LDTR_BASE, 0);
	vmwrite(GUEST_TR_BASE, vmreadz(HOST_TR_BASE));
	vmwrite(GUEST_GDTR_BASE, vmreadz(HOST_GDTR_BASE));
	vmwrite(GUEST_IDTR_BASE, vmreadz(HOST_IDTR_BASE));
	vmwrite(GUEST_DR7, 0x400);
	vmwrite(GUEST_RSP, (uint64_t)rsp);
	vmwrite(GUEST_RIP, (uint64_t)rip);
	vmwrite(GUEST_RFLAGS, 2);
	vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	vmwrite(GUEST_SYSENTER_ESP, vmreadz(HOST_IA32_SYSENTER_ESP));
	vmwrite(GUEST_SYSENTER_EIP, vmreadz(HOST_IA32_SYSENTER_EIP));
}

// code that will be run by guest
static void guest_code(void)
{
	printk(KERN_INFO "Congratulate, Enter the virtual machine!\n");
	print_regs();
	printk(KERN_INFO "Ready to execute cpuid!\n");
	asm volatile("cpuid");
	printk(KERN_INFO "Resume the virtual machine!\n");
	print_regs();
}

bool initVmcs(void) {
	g_vmStack = kzalloc(MYPAGE_SIZE,GFP_KERNEL);
	/*
	There are some areas and fields in the VMCS.(2+3+1)
	area: host-state, guest-state
	control fields: entry, execution, exit.
	information field: // it seems optional
	*/
	init_vmcs_control_fields();
	init_vmcs_host_state();
	init_vmcs_guest_state(guest_code, g_vmStack);
	return true;
}


static __always_inline void myhandler(void)
{
 	save_volatile_regs();
	printk(KERN_INFO "================Enter the Host code\n");
 	printk(KERN_INFO "Enter VM exit with reason %lu!\n", (unsigned long)vmExit_reason());
	uint64_t exit_len = vmreadz(VM_EXIT_INSTRUCTION_LEN);
	printk(KERN_INFO "Exit instruction len %lu!\n", exit_len);
	uint64_t rip = vmreadz(GUEST_RIP);
	vmwrite(GUEST_RIP, (uint64_t)rip+exit_len);

	restore_volatile_regs();
	__asm__ __volatile__("vmresume");
}

static __always_inline bool intoMatrix(void)
{
	restore_volatile_regs();
	printk(KERN_INFO "----------------Enter the Guest code\n");
	printk(KERN_INFO "Ready to execute cpuid!\n");
	asm volatile("cpuid");
	printk(KERN_INFO "Resume the virtual machine!\n");
	return true;
}

bool initVmLaunchProcess(void){
	int64_t* handler_rsp = kzalloc(MYPAGE_SIZE,GFP_KERNEL);	//this need to be deleted.
	int64_t host_rsp_data = handler_rsp;
	int64_t host_rip_data = (unsigned long)&myhandler;

	save_volatile_regs();
	__asm__ __volatile__(
		"vmwrite %[host_rsp], %[host_rsp_code];"
		"vmwrite %[host_rip], %[host_rip_code];"
		"mov %%rsp, %%rax;"
		"vmwrite %%rax, %[guest_rsp_code];"
		"lea 6(%%rip), %%rbx;"
		"vmwrite %%rbx, %[guest_rip_code];"
		"vmlaunch;"
		:
		: [host_rsp_code] "r"((uint64_t)HOST_RSP),
		  [host_rip_code] "r"((uint64_t)HOST_RIP),
		  [host_rip] "m"(host_rip_data),
		  [host_rsp] "m"(host_rsp_data),
		  [guest_rsp_code] "r"((uint64_t)GUEST_RSP),
		  [guest_rip_code] "r"((uint64_t)GUEST_RIP)
		: "memory", "cc", "rax", "rbx");
	//vmlaunch_status = vmlaunch2(input_rsp,input_rip);
	//if (vmlaunch_status != 0){
	// 	return false;
	// } else{
guest_start:
	return intoMatrix();
	//}
}

bool vmxoffOperation(void)
{
	if (deallocate_vmxon_region()) {
		printk(KERN_INFO "Successfully freed allocated vmxon region!\n");
	}
	else {
		printk(KERN_INFO "Error freeing allocated vmxon region!\n");
	}
	if (deallocate_vmcs_region()) {
		printk(KERN_INFO "Successfully freed allocated vmcs region!\n");
	}
	else {
		printk(KERN_INFO "Error freeing allocated vmcs region!\n");
	}
	asm volatile ("vmxoff\n" : : : "cc");
	return true;
}

int __init start_init(void)
{
    if (!vmxSupport()){
		printk(KERN_INFO "VMX support not present! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "VMX support present! CONTINUING");
	}
	if (!getVmxOperation()) {
		printk(KERN_INFO "VMX Operation failed! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "VMX Operation succeeded! CONTINUING");
	}
	if (!vmcsOperations()) {
		printk(KERN_INFO "VMCS Allocation failed! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "VMCS Allocation succeeded! CONTINUING");
	}
	if (!initVmcs()) {
		printk(KERN_INFO "Initialization of VMCS Control field failed! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "Initializing of control fields to the most basic settings succeeded! CONTINUING");
	}
	if (!initVmLaunchProcess()) {
		printk(KERN_INFO "VMLAUNCH failed! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "VMLAUNCH succeeded! CONTINUING");
	}

    // if (!vmxoffOperation()) {
	// 	printk(KERN_INFO "VMXOFF operation failed! EXITING");
	// 	return 0;
	// }
	// else {
	// 	printk(KERN_INFO "VMXOFF Operation succeeded! CONTINUING\n");
	// }
    return 0;
}

static void __exit end_exit(void)
{
    printk(KERN_INFO "Unloading the driver\n");
	return;
}

module_init(start_init);
module_exit(end_exit);


MODULE_LICENSE("GPL V3");
MODULE_AUTHOR("Shubham Dubey");
MODULE_DESCRIPTION("ProtoVirt- A minimalistic Hypervisior ");
