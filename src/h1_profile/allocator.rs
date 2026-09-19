use std::alloc::{GlobalAlloc, Layout};
use std::marker::PhantomData;
use std::rc::Rc;

use super::schema::ALLOC_FIELDS;
use super::store;

/// Calls through Rust's global allocator only. Native allocations, allocator
/// internals, resident memory and realloc copy volume are outside this API.
pub struct ForwardingAllocator<A>(pub A);

fn record(kind: usize, old: usize, requested: usize, failed: bool) {
    store::with_local(|local| {
        let mut groups = [false; 9];
        groups[0] = true;
        for scope in 0..4 {
            groups[1 + scope] = local.active & (1 << scope) != 0;
            groups[5 + scope] = local.top == Some(scope);
        }
        for (group, enabled) in groups.into_iter().enumerate() {
            if !enabled {
                continue;
            }
            let base = group * ALLOC_FIELDS;
            local.add(base + kind, 1);
            local.add(base + 4, requested as u64);
            if !failed {
                local.add(base + 5, requested as u64);
            } else {
                local.add(base + 6, 1);
            }
            if kind == 2 {
                local.add(base + 7, old as u64);
                local.add(base + 8, requested as u64);
            }
            if kind == 3 {
                local.add(base + 9, old as u64);
            }
        }
    });
}

// SAFETY: this wrapper forwards each call exactly once to the SAME allocator,
// with unchanged pointer/layout/size, returning its pointer unchanged. It never
// dereferences user storage. The caller's GlobalAlloc preconditions therefore
// remain the backing allocator's preconditions. Accounting runs after the call
// (including null failure); failed realloc never frees the original pointer.
// Accounting uses only const TLS, fixed arrays, checked integer operations and
// atomics. No heap allocation, locks, logging, formatting, indexing by external
// input or panicking borrow is reachable. TLS registration/teardown/reentrancy,
// slot exhaustion and overflow fail open for allocation and count observer loss.
unsafe impl<A: GlobalAlloc> GlobalAlloc for ForwardingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: unchanged GlobalAlloc call, see implementation contract.
        let pointer = unsafe { self.0.alloc(layout) };
        record(0, 0, layout.size(), pointer.is_null());
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: unchanged GlobalAlloc call, see implementation contract.
        let pointer = unsafe { self.0.alloc_zeroed(layout) };
        record(1, 0, layout.size(), pointer.is_null());
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: unchanged GlobalAlloc call, see implementation contract.
        let result = unsafe { self.0.realloc(pointer, layout, new_size) };
        record(2, layout.size(), new_size, result.is_null());
        result
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: unchanged GlobalAlloc call, see implementation contract.
        unsafe { self.0.dealloc(pointer, layout) };
        record(3, layout.size(), 0, false);
    }
}

#[derive(Clone, Copy)]
pub enum Scope {
    BodyOutput = 0,
    BodyInput = 1,
    PlainWrite = 2,
    CipherWrite = 3,
}

/// Private non-Send guard; callers only receive the closure-based scope API.
/// Same-scope nesting is inclusive once; exclusive goes to the innermost scope.
struct Guard {
    previous: Option<(u8, Option<usize>)>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some((active, top)) = self.previous {
            store::with_local(|local| {
                local.active = active;
                local.top = top;
            });
        }
    }
}

/// Attribute synchronous execution only. If `f` returns a future, its later
/// execution is NOT attributed. Use this inside each `poll`, never over await.
pub fn in_scope<R>(scope: Scope, f: impl FnOnce() -> R) -> R {
    let mut guard = Guard {
        previous: None,
        _thread_bound: PhantomData,
    };
    store::with_local(|local| {
        guard.previous = Some((local.active, local.top));
        local.active |= 1 << scope as usize;
        local.top = Some(scope as usize);
    });
    let result = f();
    drop(guard);
    result
}
