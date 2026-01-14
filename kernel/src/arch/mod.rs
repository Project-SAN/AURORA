pub mod gdt;
pub mod syscall;

pub fn init(kernel_stack_top: u64) {
    gdt::init(kernel_stack_top);
    syscall::init(kernel_stack_top);
}
