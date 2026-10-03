// SPDX-License-Identifier: GPL-3.0-only
//
// uid -> name resolution straight from /etc/passwd. No NSS, no libc calls: it
// is only used to label a handful of rows in reports.

use crate::fxhash::FxHashMap;

#[derive(Debug, Clone, Default)]
pub struct UserNames {
    map: FxHashMap<u32, String>,
}

impl UserNames {
    pub fn load() -> Self {
        match std::fs::read_to_string("/etc/passwd") {
            Ok(text) => Self::parse(&text),
            Err(_) => Self::default(),
        }
    }

    pub fn parse(text: &str) -> Self {
        let mut map = FxHashMap::default();
        for line in text.lines() {
            let mut f = line.split(':');
            if let (Some(name), Some(_), Some(uid)) = (f.next(), f.next(), f.next()) {
                if let Ok(uid) = uid.parse::<u32>() {
                    map.entry(uid).or_insert_with(|| name.to_string());
                }
            }
        }
        Self { map }
    }

    pub fn name(&self, uid: u32) -> String {
        self.map
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| format!("uid {uid}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_names_and_falls_back() {
        let u = UserNames::parse("root:x:0:0::/root:/bin/sh\nkay:x:1000:100::/home/kay:/bin/zsh\n");
        assert_eq!(u.name(0), "root");
        assert_eq!(u.name(1000), "kay");
        assert_eq!(u.name(4242), "uid 4242");
    }
}
