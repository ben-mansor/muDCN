//
// μDCN Name Unit Tests
//
// This file contains unit tests for the NDN name component.
//

use udcn_transport::name::Name;
use std::str::FromStr;

#[test]
fn test_name_creation() {
    // Test creating a name from a string
    let name = Name::from("/test/path");
    assert_eq!(name.to_string(), "/test/path");
    assert_eq!(name.len(), 2);
    
    // Test creating a name from component vectors
    let components = vec!["test".to_string(), "path".to_string()];
    let name = Name::from_components(components);
    assert_eq!(name.to_string(), "/test/path");
    assert_eq!(name.len(), 2);
    
    // Test creating an empty name
    let name = Name::new();
    assert_eq!(name.to_string(), "/");
    assert_eq!(name.len(), 0);
    assert!(name.is_empty());
}

#[test]
fn test_name_components() {
    let name = Name::from("/a/b/c");
    
    // Test component access
    assert_eq!(name.get(0).unwrap(), "a");
    assert_eq!(name.get(1).unwrap(), "b");
    assert_eq!(name.get(2).unwrap(), "c");
    assert!(name.get(3).is_none());
    
    // Test component iteration
    let components: Vec<String> = name.components().map(|c| c.to_string()).collect();
    assert_eq!(components, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    
    // Test components as bytes
    let first_component_bytes = name.get_component_bytes(0).unwrap();
    assert_eq!(first_component_bytes, b"a");
}

#[test]
fn test_name_manipulation() {
    // Test appending components
    let mut name = Name::from("/test");
    name.append("path");
    assert_eq!(name.to_string(), "/test/path");
    
    // Test appending another name
    let suffix = Name::from("/suffix");
    name.append_name(&suffix);
    assert_eq!(name.to_string(), "/test/path/suffix");
    
    // Test truncating name
    name.truncate(1);
    assert_eq!(name.to_string(), "/test");
    
    // Test clearing name
    name.clear();
    assert_eq!(name.to_string(), "/");
    assert!(name.is_empty());
}

#[test]
fn test_name_comparison() {
    let name1 = Name::from("/a/b/c");
    let name2 = Name::from("/a/b/c");
    let name3 = Name::from("/a/b");
    let name4 = Name::from("/a/b/d");
    
    // Test equality
    assert_eq!(name1, name2);
    assert_ne!(name1, name3);
    assert_ne!(name1, name4);
    
    // Test comparisons
    assert!(name3 < name1);  // Shorter names come first
    assert!(name1 < name4);  // Same length, lexicographic comparison
}

#[test]
fn test_name_prefix_matching() {
    let prefix = Name::from("/a/b");
    let name1 = Name::from("/a/b/c");
    let name2 = Name::from("/a/b");
    let name3 = Name::from("/a");
    let name4 = Name::from("/a/c");
    
    // Test has_prefix method
    assert!(name1.has_prefix(&prefix));
    assert!(name2.has_prefix(&prefix));  // A name is a prefix of itself
    assert!(!name3.has_prefix(&prefix));  // Prefix is longer than name
    assert!(!name4.has_prefix(&prefix));  // Different components
    
    // Test is_prefix_of method
    assert!(prefix.is_prefix_of(&name1));
    assert!(prefix.is_prefix_of(&name2));
    assert!(!prefix.is_prefix_of(&name3));
    assert!(!prefix.is_prefix_of(&name4));
}

#[test]
fn test_name_from_str() {
    // Test FromStr implementation
    let name = Name::from_str("/test/path").unwrap();
    assert_eq!(name.to_string(), "/test/path");
    
    // Test invalid name (missing leading slash)
    let result = Name::from_str("test/path");
    assert!(result.is_err());
}

#[test]
fn test_name_to_uri() {
    // Test simple name
    let name = Name::from("/test/path");
    assert_eq!(name.to_uri(), "ndn:/test/path");
    
    // Test empty name
    let name = Name::new();
    assert_eq!(name.to_uri(), "ndn:/");
    
    // Test name with special characters
    let mut name = Name::new();
    name.append("with space");
    name.append("with/slash");
    name.append("with%percent");
    // URI encoding should handle these special characters
    assert_eq!(name.to_uri(), "ndn:/with%20space/with%2Fslash/with%25percent");
}

#[test]
fn test_name_hashing() {
    use std::collections::HashSet;
    
    // Create a set of names
    let mut names = HashSet::new();
    names.insert(Name::from("/a/b"));
    names.insert(Name::from("/a/c"));
    names.insert(Name::from("/b"));
    
    // Test set operations
    assert!(names.contains(&Name::from("/a/b")));
    assert!(names.contains(&Name::from("/a/c")));
    assert!(names.contains(&Name::from("/b")));
    assert!(!names.contains(&Name::from("/a")));
    
    // Test duplicate insertion
    names.insert(Name::from("/a/b"));  // Duplicate, should not change set size
    assert_eq!(names.len(), 3);
}

#[test]
fn test_name_with_numeric_components() {
    // Test with numeric components
    let name = Name::from("/v1/api/123");
    assert_eq!(name.get(0).unwrap(), "v1");
    assert_eq!(name.get(1).unwrap(), "api");
    assert_eq!(name.get(2).unwrap(), "123");
}

#[test]
fn test_name_with_empty_components() {
    // Test with empty components (consecutive slashes)
    let name = Name::from("/a//b");
    assert_eq!(name.len(), 3);
    assert_eq!(name.get(0).unwrap(), "a");
    assert_eq!(name.get(1).unwrap(), "");  // Empty component
    assert_eq!(name.get(2).unwrap(), "b");
}
