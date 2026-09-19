//! Compile out every pool diagnostic operation in ordinary builds.
#[macro_export]
macro_rules! profile_pool_sync {
    ($phase:ident, $operation:expr) => {{
        #[cfg(feature = "bench-pool-profile")]
        {
            $crate::pool_profile::measure($crate::pool_profile::Phase::$phase, || $operation)
        }
        #[cfg(not(feature = "bench-pool-profile"))]
        {
            $operation
        }
    }};
}

#[macro_export]
macro_rules! profile_pool_event {
    ($event:ident) => {
        #[cfg(feature = "bench-pool-profile")]
        $crate::pool_profile::event($crate::pool_profile::Event::$event);
    };
}

#[macro_export]
macro_rules! profile_pool_ready {
    ($operation:expr) => {{
        #[cfg(feature = "bench-pool-profile")]
        {
            $crate::pool_profile::readiness(|| $operation)
        }
        #[cfg(not(feature = "bench-pool-profile"))]
        {
            $operation
        }
    }};
}

#[macro_export]
macro_rules! profile_pool_future {
    ($phase:ident, $operation:expr) => {{
        #[cfg(feature = "bench-pool-profile")]
        {
            $crate::pool_profile::phase_future($crate::pool_profile::Phase::$phase, $operation)
                .await
        }
        #[cfg(not(feature = "bench-pool-profile"))]
        {
            $operation.await
        }
    }};
}
