//! Shared process-fixture readiness for S4 process tests.

pub(super) fn wait_pids(path: &std::path::Path) -> (i32, i32) {
    for _ in 0..200 {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut values = text.split_whitespace().filter_map(|value| value.parse::<i32>().ok());
        if let (Some(leader), Some(grandchild)) = (values.next(), values.next()) {
            return (leader, grandchild);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("the Git wrapper did not publish its process group");
}
