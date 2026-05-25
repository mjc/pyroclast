use pyroclast::platform::{ThreadLister, UnsupportedThreadLister, linux_thread_ids_from_proc};

#[test]
fn unsupported_thread_lister_reports_clear_error() {
    let error = UnsupportedThreadLister
        .thread_ids(42)
        .expect_err("unsupported");

    assert!(error.to_string().contains("thread listing is unsupported"));
}

#[test]
fn reads_linux_thread_ids_from_proc_task_directory() {
    let root = tempfile::tempdir().expect("tempdir");
    let task_dir = root.path().join("42/task");
    std::fs::create_dir_all(task_dir.join("101")).expect("thread 101");
    std::fs::create_dir_all(task_dir.join("103")).expect("thread 103");
    std::fs::create_dir_all(task_dir.join("102")).expect("thread 102");
    std::fs::write(task_dir.join("not-a-thread"), "").expect("non thread file");

    let tids = linux_thread_ids_from_proc(root.path(), 42).expect("thread ids");

    assert_eq!(tids, vec![101, 102, 103]);
}

#[test]
fn rejects_processes_without_thread_ids() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(root.path().join("42/task")).expect("task dir");

    let error = linux_thread_ids_from_proc(root.path(), 42).expect_err("missing tids");

    assert!(error.to_string().contains("no thread ids found"));
}
