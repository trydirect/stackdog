//! Module structure tests
//!
//! These tests verify that all security modules can be imported
//! and basic module structure is correct.

#[test]
fn test_collectors_module_imports() {
    use stackdog::collectors;
    let _ = std::marker::PhantomData::<collectors::CollectorsMarker>;
}

#[test]
fn test_events_module_imports() {
    use stackdog::events;
    let _ = std::marker::PhantomData::<events::EventsMarker>;
}

#[test]
fn test_rules_module_imports() {
    use stackdog::rules;
    let _ = std::marker::PhantomData::<rules::RulesMarker>;
}

#[test]
fn test_ml_module_imports() {
    use stackdog::ml;
    let _ = std::marker::PhantomData::<ml::MlMarker>;
}

#[cfg(target_os = "linux")]
#[test]
fn test_firewall_module_imports() {
    use stackdog::firewall;
    let _ = std::marker::PhantomData::<firewall::FirewallMarker>;
}

#[test]
fn test_response_module_imports() {
    use stackdog::response;
    let _ = std::marker::PhantomData::<response::ResponseMarker>;
}

#[test]
fn test_correlator_module_imports() {
    use stackdog::correlator;
    let _ = std::marker::PhantomData::<correlator::CorrelatorMarker>;
}

#[test]
fn test_alerting_module_imports() {
    use stackdog::alerting;
    let _ = std::marker::PhantomData::<alerting::AlertingMarker>;
}

#[test]
fn test_baselines_module_imports() {
    use stackdog::baselines;
    let _ = std::marker::PhantomData::<baselines::BaselinesMarker>;
}

#[test]
fn test_database_module_imports() {
    use stackdog::database;
    let _ = std::marker::PhantomData::<database::DatabaseMarker>;
}
