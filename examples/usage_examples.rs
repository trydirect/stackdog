//! Stackdog Security Usage Examples
//!
//! This file demonstrates how to use Stackdog Security in your Rust applications.

use stackdog::{
    // Alerting
    AlertManager,
    AlertType,
    PatternMatch,
    // Rules & Detection
    RuleEngine,
    ScoringConfig,
    SecurityEvent,

    SignatureDatabase,
    SignatureMatcher,
    StatsTracker,

    // Events
    SyscallEvent,
    SyscallType,
    ThreatCategory,
    ThreatScorer,
};

use stackdog::alerting::{AlertDeduplicator, DedupConfig};

use chrono::Utc;

fn main() {
    println!("🐕 Stackdog Security - Usage Examples\n");

    // Example 1: Create and validate events
    example_events();

    // Example 2: Rule engine
    example_rule_engine();

    // Example 3: Signature detection
    example_signature_detection();

    // Example 4: Threat scoring
    example_threat_scoring();

    // Example 5: Alert management
    example_alerting();

    // Example 6: Pattern matching
    example_pattern_matching();

    println!("\n✅ All examples completed!");
}

/// Example 1: Creating and validating security events
fn example_events() {
    println!("📋 Example 1: Creating Security Events");
    println!("----------------------------------------");

    // Create a syscall event
    let execve_event = SyscallEvent::new(
        1234, // PID
        1000, // UID
        SyscallType::Execve,
        Utc::now(),
    );

    println!(
        "  Created execve event: PID={}, UID={}",
        execve_event.pid, execve_event.uid
    );

    // Create event with builder pattern
    let connect_event = SyscallEvent::builder()
        .pid(5678)
        .uid(1000)
        .syscall_type(SyscallType::Connect)
        .container_id(Some("abc123".to_string()))
        .comm(Some("curl".to_string()))
        .build();

    println!(
        "  Created connect event: PID={}, Command={:?}",
        connect_event.pid, connect_event.comm
    );

    // Convert to SecurityEvent
    let _security_event: SecurityEvent = execve_event.into();
    println!("  Converted to SecurityEvent variant");

    println!("  ✓ Events created successfully\n");
}

/// Example 2: Rule engine for security event evaluation
fn example_rule_engine() {
    println!("📋 Example 2: Rule Engine");
    println!("----------------------------------------");

    // Create rule engine
    let mut engine = RuleEngine::new();

    // Add built-in rules
    use stackdog::rules::builtin::{
        NetworkConnectionRule, ProcessExecutionRule, SyscallBlocklistRule,
    };

    // Block dangerous syscalls
    engine.register_rule(Box::new(SyscallBlocklistRule::new(vec![
        SyscallType::Ptrace,
        SyscallType::Setuid,
    ])));

    // Monitor process execution
    engine.register_rule(Box::new(ProcessExecutionRule::new()));

    // Monitor network connections
    engine.register_rule(Box::new(NetworkConnectionRule::new()));

    println!("  Registered {} rules", engine.rule_count());

    // Create test event
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234,
        1000,
        SyscallType::Ptrace,
        Utc::now(),
    ));

    // Evaluate rules
    let results = engine.evaluate(&event);
    let matches = results.iter().filter(|r| r.is_match()).count();

    println!("  Evaluated event: {} rules matched", matches);

    // Get detailed results
    let detailed = engine.evaluate_detailed(&event);
    for result in detailed {
        if result.matched() {
            println!("    ✓ Rule matched: {}", result.rule_name());
        }
    }

    println!("  ✓ Rule engine working\n");
}

/// Example 3: Signature-based threat detection
fn example_signature_detection() {
    println!("📋 Example 3: Signature Detection");
    println!("----------------------------------------");

    // Create signature database
    let db = SignatureDatabase::new();
    println!("  Loaded {} built-in signatures", db.signature_count());

    // Get signatures by category
    let crypto_sigs = db.get_signatures_by_category(&ThreatCategory::CryptoMiner);
    println!("  Crypto miner signatures: {}", crypto_sigs.len());

    let escape_sigs = db.get_signatures_by_category(&ThreatCategory::ContainerEscape);
    println!("  Container escape signatures: {}", escape_sigs.len());

    // Detect threats in event
    let event = SecurityEvent::Syscall(SyscallEvent::new(
        1234,
        1000,
        SyscallType::Ptrace,
        Utc::now(),
    ));

    let matches = db.detect(&event);
    println!("  Detected {} matching signatures", matches.len());

    for sig in matches {
        println!(
            "    ⚠️  {} (Severity: {}, Category: {})",
            sig.name(),
            sig.severity(),
            sig.category()
        );
    }

    println!("  ✓ Signature detection working\n");
}

/// Example 4: Threat scoring
fn example_threat_scoring() {
    println!("📋 Example 4: Threat Scoring");
    println!("----------------------------------------");

    // Create scorer with custom config
    let config = ScoringConfig::default()
        .with_base_score(50)
        .with_multiplier(1.2);

    let scorer = ThreatScorer::with_config(config);

    // Create test events
    let events = vec![
        SecurityEvent::Syscall(SyscallEvent::new(
            1234,
            1000,
            SyscallType::Execve,
            Utc::now(),
        )),
        SecurityEvent::Syscall(SyscallEvent::new(
            1234,
            1000,
            SyscallType::Ptrace,
            Utc::now(),
        )),
        SecurityEvent::Syscall(SyscallEvent::new(
            1234,
            1000,
            SyscallType::Mount,
            Utc::now(),
        )),
    ];

    // Calculate scores
    println!("  Calculating threat scores:");
    for (i, event) in events.iter().enumerate() {
        let score = scorer.calculate_score(event);
        println!(
            "    Event {}: Score={} (Severity={})",
            i + 1,
            score.value(),
            score.severity()
        );

        if score.is_high_or_higher() {
            println!("      ⚠️  High threat detected!");
        }
    }

    // Cumulative scoring
    let cumulative = scorer.calculate_cumulative_score(&events);
    println!(
        "  Cumulative score: {} (Severity={})",
        cumulative.value(),
        cumulative.severity()
    );

    println!("  ✓ Threat scoring working\n");
}

/// Example 5: Alert management
fn example_alerting() {
    println!("📋 Example 5: Alert Management");
    println!("----------------------------------------");

    // Create alert manager
    let mut alert_manager = AlertManager::new().expect("Failed to create manager");

    // Generate alerts
    let alert = alert_manager
        .generate_alert(
            AlertType::ThreatDetected,
            stackdog::rules::result::Severity::High,
            "Suspicious ptrace activity detected".to_string(),
            None,
        )
        .expect("Failed to generate alert");

    println!("  Generated alert: ID={}", alert.id());
    println!("  Alert count: {}", alert_manager.alert_count());

    // Acknowledge alert
    let alert_id = alert.id().to_string();
    alert_manager
        .acknowledge_alert(&alert_id)
        .expect("Failed to acknowledge");
    println!("  Alert acknowledged");

    // Get statistics
    let stats = alert_manager.get_stats();
    println!(
        "  Statistics: Total={}, New={}, Acknowledged={}, Resolved={}",
        stats.total_count, stats.new_count, stats.acknowledged_count, stats.resolved_count
    );

    // Create deduplicator
    let config = DedupConfig::default()
        .with_window_seconds(300)
        .with_aggregation(true);

    let mut dedup = AlertDeduplicator::new(config);

    // Check for duplicates
    let result = dedup.check(&alert);
    println!(
        "  Deduplication: is_duplicate={}, count={}",
        result.is_duplicate, result.count
    );

    println!("  ✓ Alert management working\n");
}

/// Example 6: Multi-event pattern matching
fn example_pattern_matching() {
    println!("📋 Example 6: Pattern Matching");
    println!("----------------------------------------");

    // Create signature matcher
    let mut matcher = SignatureMatcher::new();

    // Add pattern: execve followed by ptrace (suspicious)
    let pattern = PatternMatch::new()
        .with_syscall(SyscallType::Execve)
        .then_syscall(SyscallType::Ptrace)
        .within_seconds(60)
        .with_description("Suspicious process debugging pattern");

    matcher.add_pattern(pattern);
    println!("  Added pattern: execve -> ptrace (within 60s)");

    // Create event sequence
    let events = vec![
        SecurityEvent::Syscall(SyscallEvent::new(
            1234,
            1000,
            SyscallType::Execve,
            Utc::now(),
        )),
        SecurityEvent::Syscall(SyscallEvent::new(
            1234,
            1000,
            SyscallType::Ptrace,
            Utc::now(),
        )),
    ];

    // Match pattern
    let result = matcher.match_sequence(&events);
    println!(
        "  Pattern match: {} (confidence: {:.2})",
        if result.is_match() {
            "MATCH"
        } else {
            "NO MATCH"
        },
        result.confidence()
    );

    if result.is_match() {
        println!("    ⚠️  Suspicious pattern detected!");
        for sig in result.matches() {
            println!("    Matched: {}", sig);
        }
    }

    // Detection statistics
    let mut stats_tracker = StatsTracker::new().expect("Failed to create tracker");

    for event in &events {
        let match_result = matcher.match_single(event);
        stats_tracker.record_event(event, match_result.is_match());
    }

    let stats = stats_tracker.stats();
    println!(
        "  Detection stats: Events={}, Matches={}, Rate={:.1}%",
        stats.events_processed(),
        stats.signatures_matched(),
        stats.detection_rate() * 100.0
    );

    println!("  ✓ Pattern matching working\n");
}
