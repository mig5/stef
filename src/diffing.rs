use crate::model::MatchRecord;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct MatchDiff {
    pub removed: Vec<MatchRecord>,
    pub added: Vec<MatchRecord>,
}

impl MatchDiff {
    pub fn changed(&self) -> bool {
        !self.removed.is_empty() || !self.added.is_empty()
    }
}

fn grouped(items: &[MatchRecord]) -> BTreeMap<(String, String), Vec<MatchRecord>> {
    let mut out: BTreeMap<(String, String), Vec<MatchRecord>> = BTreeMap::new();
    for item in items {
        out.entry((item.path.clone(), item.text.clone()))
            .or_default()
            .push(item.clone());
    }
    out
}

pub fn diff_matches(before: &[MatchRecord], after: &[MatchRecord]) -> MatchDiff {
    let mut old = grouped(before);
    let mut new = grouped(after);
    let mut removed = Vec::new();
    let mut added = Vec::new();

    let mut keys = BTreeMap::<(String, String), ()>::new();
    for key in old.keys() {
        keys.insert(key.clone(), ());
    }
    for key in new.keys() {
        keys.insert(key.clone(), ());
    }

    for key in keys.keys() {
        let mut old_items = old.remove(key).unwrap_or_default();
        let mut new_items = new.remove(key).unwrap_or_default();
        let common = old_items.len().min(new_items.len());
        old_items.drain(0..common);
        new_items.drain(0..common);
        removed.extend(old_items);
        added.extend(new_items);
    }

    removed
        .sort_by(|a, b| (&a.path, a.line_number, &a.text).cmp(&(&b.path, b.line_number, &b.text)));
    added.sort_by(|a, b| (&a.path, a.line_number, &a.text).cmp(&(&b.path, b.line_number, &b.text)));
    MatchDiff { removed, added }
}

pub fn snapshots_equal(left: &[MatchRecord], right: &[MatchRecord]) -> bool {
    let mut a: Vec<_> = left
        .iter()
        .map(|m| (m.path.as_str(), m.text.as_str()))
        .collect();
    let mut b: Vec<_> = right
        .iter()
        .map(|m| (m.path.as_str(), m.text.as_str()))
        .collect();
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

pub fn window_baseline<'a, I>(snapshots: I) -> Vec<MatchRecord>
where
    I: IntoIterator<Item = &'a [MatchRecord]>,
{
    // Preserve the largest multiplicity ever seen for each path+text identity.
    // The first snapshot is expected to be the newest, so equal-length ties keep
    // its line-number representative.
    let mut best: BTreeMap<(String, String), Vec<MatchRecord>> = BTreeMap::new();
    for snapshot in snapshots {
        let groups = grouped(snapshot);
        for (identity, matches) in groups {
            if matches.len() > best.get(&identity).map_or(0, Vec::len) {
                best.insert(identity, matches);
            }
        }
    }
    best.into_values().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(path: &str, line: u64, text: &str) -> MatchRecord {
        MatchRecord {
            path: path.into(),
            line_number: line,
            byte_offset: 0,
            text: text.into(),
            spans: vec![],
        }
    }

    #[test]
    fn movement_is_not_a_change() {
        let d = diff_matches(&[m("a", 1, "secret")], &[m("a", 99, "secret")]);
        assert!(!d.changed());
    }

    #[test]
    fn changed_text_is_remove_and_add() {
        let d = diff_matches(&[m("a", 1, "old")], &[m("a", 1, "new")]);
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.added.len(), 1);
    }
}
