// Diagnostic: open the committed test fixture and print a real GeoIP lookup result.
// Usage: cargo run -p synapse-agent --example geoip_check
fn main() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let city_path = manifest.join("test-data/GeoIP2-City-Test.mmdb");
    let asn_path = manifest.join("test-data/GeoLite2-ASN-Test.mmdb");

    println!("city db : {}", city_path.display());
    println!("asn  db : {}", asn_path.display());

    let city_reader = maxminddb::Reader::open_readfile(&city_path).expect("open city DB");
    let asn_reader = maxminddb::Reader::open_readfile(&asn_path).expect("open ASN DB");

    for ip_str in &["81.2.69.142", "1.128.0.123", "8.8.8.8", "192.168.1.1"] {
        let ip: std::net::IpAddr = ip_str.parse().unwrap();

        let country = city_reader
            .lookup(ip)
            .ok()
            .and_then(|r| r.decode::<maxminddb::geoip2::City>().ok().flatten())
            .and_then(|c| c.country.iso_code.map(|s| s.to_string()))
            .unwrap_or_else(|| "(none)".into());

        let asn = asn_reader
            .lookup(ip)
            .ok()
            .and_then(|r| r.decode::<maxminddb::geoip2::Asn>().ok().flatten())
            .and_then(|a| a.autonomous_system_number)
            .map(|n| n.to_string())
            .unwrap_or_else(|| "(none)".into());

        println!("{:<16} country={:<6} asn={}", ip_str, country, asn);
    }
}
