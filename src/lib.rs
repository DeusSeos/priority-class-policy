use std::collections::HashSet;

use guest::prelude::*;
use k8s_openapi::api::core::v1 as apicore;
use kubewarden_policy_sdk::wapc_guest as guest;
use lazy_static::lazy_static;
extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};
use slog::{error, o, warn, Logger};

use settings::Settings;
mod settings;

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "priority-class-policy")
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    let allowed = &validation_request.settings.allowed_priority_classes;
    let denied = &validation_request.settings.denied_priority_classes;

    match validation_request.extract_pod_spec_from_object() {
        Ok(Some(pod_spec)) => match validate_pod_priority_class(pod_spec, allowed, denied) {
            Ok(_) => kubewarden::accept_request(),
            Err(err) => kubewarden::reject_request(Some(err), None, None, None),
        },
        Ok(None) => {
            warn!(LOG_DRAIN, "no PodSpec found");
            kubewarden::accept_request()
        }
        Err(err) => {
            error!(LOG_DRAIN, "Priority class policy failed to extract PodSpec from the request"; "err" => %err);
            kubewarden::reject_request(
                Some(format!(
                    "Priority class policy failed to extract PodSpec from the request : {err}"
                )),
                None,
                None,
                None,
            )
        }
    }
}

fn validate_pod_priority_class(
    pod: apicore::PodSpec,
    allowed_priority_classes: &Option<HashSet<String>>,
    denied_priority_classes: &Option<HashSet<String>>,
) -> Result<(), String> {
    let priority_class_name = match &pod.priority_class_name {
        Some(pc) => pc,
        None => {
            // If no priority class is set, we consider it valid if no restrictions are applied
            return Ok(());
        }
    };

    match (allowed_priority_classes, denied_priority_classes) {
        (Some(allowed), None) => {
            if !allowed.contains(priority_class_name) {
                return Err(format!(
                    "Priority class \"{}\" is not in allowed list.",
                    priority_class_name
                ));
            }
        }
        (None, Some(denied)) => {
            if denied.contains(priority_class_name) {
                return Err(format!(
                    "Priority class \"{}\" is in denied list.",
                    priority_class_name
                ));
            }
        }
        _ => {
            return Err(
                "Policy misconfigured: must set exactly one of allowed_priority_classes or denied_priority_classes"
                    .to_string(),
            )
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_pod_priority_class;
    use rstest::rstest;
    use std::collections::HashSet;

    use k8s_openapi::api::core::v1::PodSpec;

    #[rstest]
    #[case(Some("low-priority".to_string()), Some(HashSet::from(["high-priority".to_string(), "low-priority".to_string()])), None, true)]
    #[case(Some("no-priority".to_string()), Some(HashSet::from(["high-priority".to_string(), "low-priority".to_string()])), None, false)]
    #[case(Some("high-priority".to_string()),  None, Some(HashSet::from(["high-priority".to_string(), "low-priority".to_string()])), false)]
    #[case(None, Some(HashSet::from(["high-priority".to_string(), "low-priority".to_string()])), None, true)]
    fn test_pod_validation(
        #[case] pod_priority_class: Option<String>,
        #[case] allowed_classes: Option<HashSet<String>>,
        #[case] denied_classes: Option<HashSet<String>>,
        #[case] should_succeed: bool,
    ) {
        let pod = PodSpec {
            priority_class_name: pod_priority_class,
            ..Default::default()
        };
        let result = validate_pod_priority_class(pod, &allowed_classes, &denied_classes);
        assert_eq!(result.is_ok(), should_succeed);
    }
}
