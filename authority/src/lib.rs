//! Minimal placeholder for the authority crate.

pub fn hello() -> &'static str {
    "hello, world"
}

#[cfg(test)]
mod tests {
    use super::hello;

    #[test]
    fn returns_hello_world() {
        assert_eq!(hello(), "hello, world");
    }
}
