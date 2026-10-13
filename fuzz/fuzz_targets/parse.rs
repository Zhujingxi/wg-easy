#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else { return };
    if let Ok(config) = wge_config::parse(input) {
        config.validate().unwrap();
        let output = wge_config::write(&config).unwrap();
        assert_eq!(wge_config::parse(&output).unwrap(), config);
        let public = config.public();
        public.validate().unwrap();
        for route in public.allowed_ips() {
            let coverage = wge_config::coverage(route);
            assert!(route.contains(coverage.first));
            assert!(route.contains(coverage.last));
        }
    }
});
