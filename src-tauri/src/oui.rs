use std::collections::HashMap;
use std::sync::LazyLock;

static OUI_TOML: &str = include_str!("../oui.toml");

static OUI_TABLE: LazyLock<HashMap<[u8; 3], &'static str>> = LazyLock::new(|| {
    let raw: HashMap<String, String> = toml::from_str(OUI_TOML).unwrap_or_default();
    let mut map = HashMap::with_capacity(raw.len());
    for (prefix_str, vendor) in &raw {
        let parts: Vec<&str> = prefix_str.split(':').collect();
        if parts.len() == 3 {
            if let (Some(a), Some(b), Some(c)) = (
                u8::from_str_radix(parts[0], 16).ok(),
                u8::from_str_radix(parts[1], 16).ok(),
                u8::from_str_radix(parts[2], 16).ok(),
            ) {
                let vendor: &'static str = Box::leak(vendor.clone().into_boxed_str());
                map.insert([a, b, c], vendor);
            }
        }
    }
    map
});

pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let prefix = [
        u8::from_str_radix(parts[0], 16).ok()?,
        u8::from_str_radix(parts[1], 16).ok()?,
        u8::from_str_radix(parts[2], 16).ok()?,
    ];
    OUI_TABLE.get(&prefix).copied()
}
