use std::collections::HashMap;
use std::sync::LazyLock;

static OUI_TOML: &str = include_str!("../oui.toml");

static OUI_TABLE: LazyLock<HashMap<[u8; 3], String>> = LazyLock::new(|| {
    let raw: HashMap<String, String> = toml::from_str(OUI_TOML).unwrap_or_default();
    let mut map = HashMap::with_capacity(raw.len());
    for (prefix_str, vendor) in raw {
        let mut parts = prefix_str.split(':');
        if let (Some(a), Some(b), Some(c), None) = (
            parts.next().and_then(|p| u8::from_str_radix(p, 16).ok()),
            parts.next().and_then(|p| u8::from_str_radix(p, 16).ok()),
            parts.next().and_then(|p| u8::from_str_radix(p, 16).ok()),
            parts.next(),
        ) {
            map.insert([a, b, c], vendor);
        }
    }
    map
});

/// Look up the vendor for a raw MAC address (at least the 3 OUI bytes).
pub fn lookup_vendor(mac: &[u8]) -> Option<&'static str> {
    let prefix: [u8; 3] = mac.get(..3)?.try_into().ok()?;
    OUI_TABLE.get(&prefix).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundled table is a compile-time input; if it ever fails to parse,
    /// every vendor-based inference silently degrades. Catch that here.
    #[test]
    fn bundled_table_parses_and_resolves() {
        assert!(!OUI_TABLE.is_empty(), "bundled oui.toml failed to parse");
        // 00:1b:1b is Siemens in the bundled table (also used by import tests)
        assert_eq!(
            lookup_vendor(&[0x00, 0x1b, 0x1b, 0x44, 0x55, 0x66]),
            Some("Siemens")
        );
    }
}
