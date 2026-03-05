use std::net::IpAddr;
use std::str::FromStr;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

use crate::protocol::GeoInfo;

pub struct Enricher {
    resolver: TokioAsyncResolver,
    geoip: Option<maxminddb::Reader<Vec<u8>>>,
}

impl Enricher {
    pub fn new(geoip_path: Option<&str>) -> Self {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let geoip = geoip_path.and_then(|path| {
            match maxminddb::Reader::open_readfile(path) {
                Ok(reader) => Some(reader),
                Err(e) => {
                    tracing::error!("Failed to load GeoIP database from {}: {}", path, e);
                    None
                }
            }
        });

        if geoip.is_some() {
            tracing::info!("GeoIP database loaded");
        }

        Enricher { resolver, geoip }
    }

    /// Perform a reverse DNS lookup for the given IP address.
    /// Returns the first PTR record hostname, or None if the lookup fails.
    pub async fn reverse_dns(&self, ip: &str) -> Option<String> {
        let addr: IpAddr = IpAddr::from_str(ip).ok()?;
        let result = self.resolver.reverse_lookup(addr).await.ok()?;
        result
            .iter()
            .next()
            .map(|name| name.to_string().trim_end_matches('.').to_string())
    }

    /// Look up GeoIP information for the given IP address.
    /// Requires a loaded MaxMind City database. Returns None if no database
    /// is loaded or the IP is not found.
    pub fn geoip_lookup(&self, ip: &str) -> Option<GeoInfo> {
        let reader = self.geoip.as_ref()?;
        let addr: IpAddr = IpAddr::from_str(ip).ok()?;

        let city: maxminddb::geoip2::City = reader.lookup(addr).ok()?;

        Some(GeoInfo {
            country: city
                .country
                .and_then(|c| c.iso_code.map(|s| s.to_string())),
            city: city
                .city
                .and_then(|c| c.names)
                .and_then(|n| n.get("en").map(|s| s.to_string())),
            latitude: city.location.as_ref().and_then(|l| l.latitude),
            longitude: city.location.as_ref().and_then(|l| l.longitude),
            asn: None,    // Requires separate ASN database
            as_org: None, // Requires separate ASN database
        })
    }

    /// Classify whether an IP address is in a private/reserved range (RFC 1918, loopback, link-local).
    pub fn is_private(ip: &str) -> bool {
        match IpAddr::from_str(ip) {
            Ok(IpAddr::V4(v4)) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            Ok(IpAddr::V6(v6)) => v6.is_loopback(),
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_rfc1918() {
        assert!(Enricher::is_private("10.0.0.1"));
        assert!(Enricher::is_private("172.16.0.1"));
        assert!(Enricher::is_private("192.168.1.1"));
        assert!(Enricher::is_private("127.0.0.1"));
        assert!(Enricher::is_private("169.254.1.1"));
    }

    #[test]
    fn test_is_private_public() {
        assert!(!Enricher::is_private("8.8.8.8"));
        assert!(!Enricher::is_private("1.1.1.1"));
        assert!(!Enricher::is_private("203.0.113.1"));
    }

    #[test]
    fn test_is_private_invalid() {
        assert!(!Enricher::is_private("not-an-ip"));
        assert!(!Enricher::is_private(""));
    }

    #[test]
    fn test_geoip_lookup_no_database() {
        let enricher = Enricher::new(None);
        let result = enricher.geoip_lookup("8.8.8.8");
        assert!(result.is_none());
    }

    #[test]
    fn test_geoip_lookup_invalid_ip() {
        let enricher = Enricher::new(None);
        let result = enricher.geoip_lookup("not-an-ip");
        assert!(result.is_none());
    }
}
