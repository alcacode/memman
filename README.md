# memman
Attempt at a memory mangement system, though it probably would be more fair to call it an self-compacting array. Obviously this is not a new idea, and there are plenty of similar--probably better--implementations out there, this is simply my take.

The idea is to allow rapid memory allocation, all the while keeping everything not only within a continuous memory region but also crammed together by always reusing deallocated blocks in order to allow the CPU cache as efficiently as possible. This is done by using deallocated blocks as temporary storage for a pointer to the next free block, which together create a linked list of all free blocks with 0 additional memory overhead.
