// All observer arguments disappear from default builds, including clock reads.
macro_rules! udp_count {
    ($counter:ident, $amount:expr) => {{
        #[cfg(feature = "bench-udp-profile")]
        crate::udp_profile::count(crate::udp_profile::schema::Counter::$counter, $amount as u64);
    }};
}

macro_rules! udp_timed {
    ($operation:ident, $expression:expr) => {{
        #[cfg(feature = "bench-udp-profile")]
        let result = crate::udp_profile::timed(
            crate::udp_profile::schema::Operation::$operation,
            || $expression,
        );
        #[cfg(not(feature = "bench-udp-profile"))]
        let result = $expression;
        result
    }};
}

macro_rules! udp_lookup {
    ($operation:ident, $expression:expr) => {{
        let result = udp_timed!($operation, $expression);
        #[cfg(feature = "bench-udp-profile")]
        crate::udp_profile::lookup_outcome(
            crate::udp_profile::schema::Operation::$operation,
            result.is_some(),
        );
        result
    }};
}

macro_rules! udp_poll {
    ($reply:expr, $expression:expr) => {{
        #[cfg(feature = "bench-udp-profile")]
        let future = crate::udp_profile::observe_polls($expression, $reply);
        #[cfg(not(feature = "bench-udp-profile"))]
        let future = $expression;
        future
    }};
}

macro_rules! udp_drain {
    ($reply:expr, $expression:expr) => {{
        let result = $expression;
        #[cfg(feature = "bench-udp-profile")]
        if result
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
        {
            if $reply {
                udp_count!(BackendEmptyDrain, 1);
            } else {
                udp_count!(IngressEmptyDrain, 1);
            }
        }
        result
    }};
}

macro_rules! udp_direct {
    ($expression:expr) => {{
        #[cfg(feature = "bench-udp-profile")]
        let future = crate::udp_profile::observe_direct_send($expression);
        #[cfg(not(feature = "bench-udp-profile"))]
        let future = $expression;
        future
    }};
}
