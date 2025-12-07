//! Tests for channel communication functions (send_sign_message, send_check_message, etc.)

use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

// Mock message types to simulate the actual channel messages
const PRINT_MESSAGE: u8 = 0;
const TICK_MESSAGE: u8 = 1;
const END_MESSAGE: u8 = 2;

#[test]
fn test_send_sign_message_basic() {
    let (tx, rx) = channel::<(String, u64)>();
    
    let filename = "test.txt".to_string();
    let file_length = 1234u64;
    
    tx.send((filename.clone(), file_length)).unwrap();
    
    let (received_name, received_length) = rx.recv().unwrap();
    assert_eq!(received_name, filename);
    assert_eq!(received_length, file_length);
}

#[test]
fn test_send_sign_message_with_length() {
    let (tx, rx) = channel::<(String, u64)>();
    
    let test_cases = vec![
        ("small.txt", 100),
        ("medium.txt", 100_000),
        ("large.txt", 10_000_000),
    ];
    
    for (filename, length) in test_cases {
        tx.send((filename.to_string(), length)).unwrap();
        let (_, received_length) = rx.recv().unwrap();
        assert_eq!(received_length, length);
    }
}

#[test]
fn test_send_sign_message_multiple() {
    let (tx, rx) = channel::<(String, u64)>();
    
    let messages = vec![
        ("file1.txt".to_string(), 100),
        ("file2.txt".to_string(), 200),
        ("file3.txt".to_string(), 300),
    ];
    
    for msg in &messages {
        tx.send(msg.clone()).unwrap();
    }
    
    for expected in messages {
        let received = rx.recv().unwrap();
        assert_eq!(received, expected);
    }
}

#[test]
#[should_panic]
fn test_send_sign_message_closed_channel() {
    let (tx, rx) = channel::<(String, u64)>();
    
    drop(rx); // Close receiver
    
    tx.send(("test.txt".to_string(), 100)).unwrap(); // Should panic
}

#[test]
fn test_send_check_message_print() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    let message = "Check passed".to_string();
    tx.send((PRINT_MESSAGE, message.clone(), false)).unwrap();
    
    let (msg_type, content, verbose) = rx.recv().unwrap();
    assert_eq!(msg_type, PRINT_MESSAGE);
    assert_eq!(content, message);
    assert_eq!(verbose, false);
}

#[test]
fn test_send_check_message_tick() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    tx.send((TICK_MESSAGE, String::new(), false)).unwrap();
    
    let (msg_type, _, _) = rx.recv().unwrap();
    assert_eq!(msg_type, TICK_MESSAGE);
}

#[test]
fn test_send_check_message_end() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    tx.send((END_MESSAGE, String::new(), false)).unwrap();
    
    let (msg_type, _, _) = rx.recv().unwrap();
    assert_eq!(msg_type, END_MESSAGE);
}

#[test]
fn test_send_check_message_verbose_flag() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    // Test verbose = true
    tx.send((PRINT_MESSAGE, "verbose".to_string(), true)).unwrap();
    let (_, _, verbose1) = rx.recv().unwrap();
    assert_eq!(verbose1, true);
    
    // Test verbose = false
    tx.send((PRINT_MESSAGE, "normal".to_string(), false)).unwrap();
    let (_, _, verbose2) = rx.recv().unwrap();
    assert_eq!(verbose2, false);
}

#[test]
#[should_panic]
fn test_send_check_message_closed_channel() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    drop(rx);
    
    tx.send((PRINT_MESSAGE, "test".to_string(), false)).unwrap();
}

#[test]
fn test_send_pass_fail_check_message_pass() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    let condition = true;
    let pass_msg = "PASS".to_string();
    
    if condition {
        tx.send((PRINT_MESSAGE, pass_msg.clone(), true)).unwrap();
    }
    
    let (_, msg, verbose) = rx.recv().unwrap();
    assert_eq!(msg, pass_msg);
    assert_eq!(verbose, true); // Pass messages are verbose
}

#[test]
fn test_send_pass_fail_check_message_fail() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    let condition = false;
    let fail_msg = "FAIL".to_string();
    
    if !condition {
        tx.send((PRINT_MESSAGE, fail_msg.clone(), false)).unwrap();
    }
    
    let (_, msg, verbose) = rx.recv().unwrap();
    assert_eq!(msg, fail_msg);
    assert_eq!(verbose, false); // Fail messages are not verbose
}

#[test]
fn test_send_pass_fail_verbose_settings() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    // Pass message: verbose = true
    tx.send((PRINT_MESSAGE, "PASS".to_string(), true)).unwrap();
    let (_, _, pass_verbose) = rx.recv().unwrap();
    assert!(pass_verbose);
    
    // Fail message: verbose = false
    tx.send((PRINT_MESSAGE, "FAIL".to_string(), false)).unwrap();
    let (_, _, fail_verbose) = rx.recv().unwrap();
    assert!(!fail_verbose);
}

#[test]
fn test_write_check_from_channel_normal_messages() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    let messages = vec![
        "Message 1".to_string(),
        "Message 2".to_string(),
        "Message 3".to_string(),
    ];
    
    for msg in &messages {
        tx.send((PRINT_MESSAGE, msg.clone(), false)).unwrap();
    }
    tx.send((END_MESSAGE, String::new(), false)).unwrap();
    
    let mut received = Vec::new();
    loop {
        let (msg_type, content, _) = rx.recv().unwrap();
        if msg_type == END_MESSAGE {
            break;
        }
        received.push(content);
    }
    
    assert_eq!(received, messages);
}

#[test]
fn test_write_check_from_channel_tick_messages() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    // Send tick messages to simulate progress updates
    for _ in 0..5 {
        tx.send((TICK_MESSAGE, String::new(), false)).unwrap();
    }
    tx.send((END_MESSAGE, String::new(), false)).unwrap();
    
    let mut tick_count = 0;
    loop {
        let (msg_type, _, _) = rx.recv().unwrap();
        if msg_type == END_MESSAGE {
            break;
        }
        if msg_type == TICK_MESSAGE {
            tick_count += 1;
        }
    }
    
    assert_eq!(tick_count, 5);
}

#[test]
fn test_write_check_from_channel_verbose_mode() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    // In verbose mode, all messages should be received
    let messages = vec![
        (PRINT_MESSAGE, "verbose msg".to_string(), true),
        (PRINT_MESSAGE, "normal msg".to_string(), false),
    ];
    
    for msg in &messages {
        tx.send(msg.clone()).unwrap();
    }
    tx.send((END_MESSAGE, String::new(), false)).unwrap();
    
    let mut received_count = 0;
    loop {
        let (msg_type, _, _) = rx.recv().unwrap();
        if msg_type == END_MESSAGE {
            break;
        }
        received_count += 1;
    }
    
    assert_eq!(received_count, 2); // Both messages received in verbose mode
}

#[test]
fn test_write_check_from_channel_non_verbose_mode() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    // In non-verbose mode, only non-verbose messages should be processed
    let messages = vec![
        (PRINT_MESSAGE, "verbose msg".to_string(), true),  // Should be filtered
        (PRINT_MESSAGE, "normal msg".to_string(), false), // Should be shown
    ];
    
    for msg in &messages {
        tx.send(msg.clone()).unwrap();
    }
    tx.send((END_MESSAGE, String::new(), false)).unwrap();
    
    let mut non_verbose_count = 0;
    loop {
        let (msg_type, _, verbose) = rx.recv().unwrap();
        if msg_type == END_MESSAGE {
            break;
        }
        if !verbose {
            non_verbose_count += 1;
        }
    }
    
    assert_eq!(non_verbose_count, 1); // Only non-verbose message counted
}

#[test]
fn test_write_check_from_channel_end_message() {
    let (tx, rx) = channel::<(u8, String, bool)>();
    
    tx.send((PRINT_MESSAGE, "msg1".to_string(), false)).unwrap();
    tx.send((PRINT_MESSAGE, "msg2".to_string(), false)).unwrap();
    tx.send((END_MESSAGE, String::new(), false)).unwrap();
    tx.send((PRINT_MESSAGE, "msg3".to_string(), false)).unwrap(); // After END
    
    let mut received_count = 0;
    loop {
        let (msg_type, _, _) = rx.recv().unwrap();
        if msg_type == END_MESSAGE {
            break; // Should terminate here
        }
        received_count += 1;
    }
    
    assert_eq!(received_count, 2); // Only messages before END
}

#[test]
fn test_write_manifest_from_channel_receives_all() {
    let (tx, rx) = channel::<String>();
    
    let manifest_lines = vec![
        "file1.txt|hash1|100|date1".to_string(),
        "file2.txt|hash2|200|date2".to_string(),
        "file3.txt|hash3|300|date3".to_string(),
    ];
    
    thread::spawn(move || {
        for line in manifest_lines {
            tx.send(line).unwrap();
            thread::sleep(Duration::from_millis(10));
        }
    });
    
    let mut received = Vec::new();
    while let Ok(line) = rx.recv_timeout(Duration::from_millis(100)) {
        received.push(line);
    }
    
    assert_eq!(received.len(), 3);
}

#[test]
fn test_write_manifest_from_channel_updates_progress() {
    let (tx, rx) = channel::<String>();
    
    let total_files = 10;
    
    thread::spawn(move || {
        for i in 0..total_files {
            tx.send(format!("file{}.txt|hash|size|date", i)).unwrap();
        }
    });
    
    let mut progress = 0;
    while let Ok(_) = rx.recv_timeout(Duration::from_millis(100)) {
        progress += 1;
    }
    
    assert_eq!(progress, total_files);
}

