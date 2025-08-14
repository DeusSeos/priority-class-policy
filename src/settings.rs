use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct Settings {
    pub allowed_priority_classes: Option<HashSet<String>>,
    pub denied_priority_classes: Option<HashSet<String>>,
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        match (&self.allowed_priority_classes, &self.denied_priority_classes) {
            (Some(allowed), Some(denied)) if !allowed.is_empty() && !denied.is_empty() => {
                Err("Both allowed and denied priority classes are set. Please use only one.".to_string())
            }
            (Some(allowed), None) if allowed.is_empty() => {
                Err("Allowed priority classes cannot be empty.".to_string())
            }
            (None, Some(denied)) if denied.is_empty() => {
                Err("Denied priority classes cannot be empty.".to_string())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_empty_settings() {
        let settings = Settings {
            ..Default::default()
        };
        assert!(settings.validate().is_err());
    }

    #[test]
    fn validate_nonempty_allowed_settings() {
        let settings = Settings {

            allowed_priority_classes: Some(HashSet::from([
                "high-priority".to_string(),
                "low-priority".to_string(),
            ])),
            denied_priority_classes: None,
        };
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn validate_nonempty_denied_settings() {
        let settings = Settings {
            allowed_priority_classes: None,
            denied_priority_classes: Some(HashSet::from([
                "high-priority".to_string(),
                "low-priority".to_string(),
            ])),
        };
        assert!(settings.validate().is_ok());

    }

    #[test]
    fn validate_both_allowed_and_denied_settings() {
        let settings = Settings {
            allowed_priority_classes: Some(HashSet::from([
                "high-priority".to_string(),
                "low-priority".to_string(),
            ])),
            denied_priority_classes: Some(HashSet::from([
                "medium-priority".to_string(),
                "urgent-priority".to_string(),
            ])),
        };
        assert!(settings.validate().is_err());
    }

    



}
