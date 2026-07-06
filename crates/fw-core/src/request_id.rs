use ulid::Ulid;

pub fn generate_request_id() -> String {
    Ulid::new().to_string()
}
