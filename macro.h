#define MYPAGE_SIZE 4096
#define X86_CR4_VMXE_BIT	13 /* enable VMX virtualization */
#define X86_CR4_VMXE		_BITUL(X86_CR4_VMXE_BIT)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1<<2)
#define FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX	(1<<1)
#define FEATURE_CONTROL_LOCKED				(1<<0)
#define MSR_IA32_FEATURE_CONTROL        0x0000003a
#define MSR_IA32_VMX_BASIC              0x00000480

// for vmcs control field
#define MSR_IA32_VMX_PINBASED_CTLS		0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS		0x00000482
#define MSR_IA32_VMX_PROCBASED_CTLS2	0x0000048b
#define MSR_IA32_VMX_EXIT_CTLS			0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS			0x00000484
// CH B.3.1
// Table B-8. Encodings for 32-Bit Control Fields
#define PIN_BASED_VM_EXEC_CONTROLS		0x00004000
#define PROC_BASED_VM_EXEC_CONTROLS		0x00004002
#define PROC2_BASED_VM_EXEC_CONTROLS	0x0000401e
#define VM_EXIT_CONTROLS				0x0000400c
#define VM_ENTRY_CONTROLS				0x00004012
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS	0x80000000
#define VIRTUAL_PROCESSOR_ID			0x00000000
#define POSTED_INTR_NV					0x00000002
#define PAGE_FAULT_ERROR_CODE_MASK		0x00004006
#define PAGE_FAULT_ERROR_CODE_MATCH		0x00004008
#define CR3_TARGET_COUNT				0x0000400a
#define VM_EXIT_HOST_ADDR_SPACE_SIZE	0x00000200
#define VM_EXIT_MSR_STORE_COUNT			0x0000400e
#define VM_EXIT_MSR_LOAD_COUNT			0x00004010
#define TPR_THRESHOLD					0x0000401c
#define VM_ENTRY_MSR_LOAD_COUNT			0x00004014
#define VM_ENTRY_INTR_INFO_FIELD		0x00004016
#define CR0_GUEST_HOST_MASK				0x00006000
#define CR4_GUEST_HOST_MASK				0x00006002
#define CR0_READ_SHADOW					0x00006004
#define CR4_READ_SHADOW					0x00006006
#define VM_ENTRY_IA32E_MODE				0x00000200


#define EXCEPTION_BITMAP				0x00004004
// CH B.2.1
// Table B-4. Encodings for 64-Bit Control Fields
#define EPT_POINTER						0x0000201a



// for checks on host control registers
#define HOST_CR0						0x00006c00
#define	HOST_CR3						0x00006c02
#define	HOST_CR4						0x00006c04
// CH B.1.3, Vol 3
#define HOST_ES_SELECTOR				0x00000c00
#define HOST_CS_SELECTOR				0x00000c02
#define HOST_SS_SELECTOR				0x00000c04
#define HOST_DS_SELECTOR				0x00000c06
#define HOST_FS_SELECTOR				0x00000c08
#define HOST_GS_SELECTOR				0x00000c0a
#define HOST_TR_SELECTOR				0x00000c0c
#define HOST_FS_BASE					0x00006c06
#define HOST_GS_BASE					0x00006c08
#define HOST_TR_BASE					0x00006c0a
#define HOST_GDTR_BASE					0x00006c0c
#define HOST_IDTR_BASE					0x00006c0e
#define HOST_IA32_SYSENTER_ESP			0x00006c10
#define HOST_IA32_SYSENTER_EIP			0x00006c12
#define HOST_IA32_SYSENTER_CS			0x00004c00
#define HOST_RSP						0x00006c14
#define	HOST_RIP						0x00006c16
#define VM_EXIT_LOAD_IA32_PAT			0x00080000
#define VM_EXIT_LOAD_IA32_EFER			0x00200000
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL	0x00001000
#define MSR_IA32_CR_PAT					0x00000277
#define MSR_EFER						0xc0000080
#define MSR_CORE_PERF_GLOBAL_CTRL		0x0000038f
#define HOST_IA32_PAT					0x00002c00
#define HOST_IA32_EFER					0x00002c02
#define HOST_IA32_PERF_GLOBAL_CTRL		0x00002c04

// for Initializing guest control area
// CH B.1.2, Vol 3
#define GUEST_ES_SELECTOR				0x00000800
#define GUEST_CS_SELECTOR				0x00000802
#define GUEST_SS_SELECTOR				0x00000804
#define GUEST_DS_SELECTOR				0x00000806
#define GUEST_FS_SELECTOR				0x00000808
#define GUEST_GS_SELECTOR				0x0000080a
#define GUEST_LDTR_SELECTOR				0x0000080c
#define GUEST_TR_SELECTOR				0x0000080e
// CH B.1.3, Vol 3
#define GUEST_IA32_DEBUGCTL				0x00002802
#define GUEST_IA32_PAT					0x00002804
#define GUEST_IA32_EFER					0x00002806
#define GUEST_IA32_PERF_GLOBAL_CTRL		0x00002808
// CH B.3.3, Vol 3
#define GUEST_ES_LIMIT					0x00004800
#define GUEST_CS_LIMIT					0x00004802
#define GUEST_SS_LIMIT					0x00004804
#define GUEST_DS_LIMIT					0x00004806
#define GUEST_FS_LIMIT					0x00004808
#define GUEST_GS_LIMIT					0x0000480a
#define GUEST_LDTR_LIMIT				0x0000480c
#define GUEST_TR_LIMIT					0x0000480e
#define GUEST_GDTR_LIMIT				0x00004810
#define GUEST_IDTR_LIMIT				0x00004812
#define GUEST_ES_AR_BYTES				0x00004814
#define GUEST_CS_AR_BYTES				0x00004816
#define GUEST_SS_AR_BYTES				0x00004818
#define GUEST_DS_AR_BYTES				0x0000481a
#define GUEST_FS_AR_BYTES				0x0000481c
#define GUEST_GS_AR_BYTES				0x0000481e
#define GUEST_LDTR_AR_BYTES				0x00004820
#define GUEST_TR_AR_BYTES				0x00004822
// CH B.4.3, Vol 3
#define GUEST_CR0						0x00006800
#define GUEST_CR3						0x00006802
#define GUEST_CR4						0x00006804
#define GUEST_ES_BASE					0x00006806
#define GUEST_CS_BASE					0x00006808
#define GUEST_SS_BASE					0x0000680a
#define GUEST_DS_BASE					0x0000680c
#define GUEST_FS_BASE					0x0000680e
#define GUEST_GS_BASE					0x00006810
#define GUEST_LDTR_BASE					0x00006812
#define GUEST_TR_BASE					0x00006814
#define GUEST_GDTR_BASE					0x00006816
#define GUEST_IDTR_BASE					0x00006818
#define GUEST_DR7						0x0000681a
#define	GUEST_RSP						0x0000681c
#define	GUEST_RIP						0x0000681e
#define	GUEST_RFLAGS					0x00006820
#define VMCS_LINK_POINTER				0x00002800
#define GUEST_INTR_STATUS				0x00000810
#define GUEST_PML_INDEX					0x00000812
#define GUEST_INTERRUPTIBILITY_INFO		0x00004824
#define GUEST_ACTIVITY_STATE			0X00004826
#define GUEST_SYSENTER_CS				0x0000482A
#define VMX_PREEMPTION_TIMER_VALUE		0x0000482E
#define GUEST_PENDING_DBG_EXCEPTIONS	0x00006822
#define GUEST_SYSENTER_ESP				0x00006824
#define GUEST_SYSENTER_EIP				0x00006826

#define ACTIVATE_SECONDARY_CONTROLS		(1<<31)

#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_SYSENTER_CS			0x00000174

#define VM_EXIT_REASON			 		0x00004402
#define VM_INSTRUCTION_ERROR			0x00004000  // CH 26.1, Vol 3
#define EAX_EDX_VAL(val, low, high)	((low) | (high) << 32)
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)
