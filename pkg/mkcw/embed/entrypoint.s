	.section	.rodata.1,"aMS",@progbits,1
msg:
	.string	"This image is designed to be run as a confidential workload using libkrun.\n"
	.section	.text._start,"ax",@progbits
	.globl	_start
	.type	_start,@function
_start:
	movq	$1, %rax
	movq	$2, %rdi
	movq	$msg, %rsi
	movq	$75, %rdx
	syscall
	movq	$60, %rax
	movq	$1, %rdi
	syscall
	.section	.note.GNU-stack,"",@progbits
