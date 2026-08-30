//! Static regression guards for README license TL;DR (#4273).
//!
//! Ensures the license section does not contradict LICENSE / LICENSE-COMMERCIAL.md.

const README: &str = include_str!("../../../README.md");

fn readme_license_section() -> &'static str {
    const MARKER: &str = "## License";
    let start = README
        .find(MARKER)
        .expect("README must contain a ## License section");
    &README[start..]
}

#[test]
fn readme_license_section_matches_commercial_terms() {
    let section = readme_license_section();
    let lower = section.to_ascii_lowercase();

    assert!(
        !lower.contains("resell"),
        "README license section must not frame free use as 'unless reselling'"
    );
    assert!(
        !lower.contains("proof-of-concept") && !lower.contains("proof of concept"),
        "README license section must not grant a free corporate proof-of-concept carve-out"
    );
    assert!(
        !lower.contains("demo"),
        "README license section must not grant a free corporate demo carve-out"
    );
    assert!(
        !lower.contains("kick the tires"),
        "README license section must not imply casual free corporate evaluation"
    );

    assert!(
        section.contains("(LICENSE)"),
        "README license section must link to LICENSE"
    );
    assert!(
        section.contains("(LICENSE-COMMERCIAL.md)"),
        "README license section must link to LICENSE-COMMERCIAL.md"
    );
    assert!(
        lower.contains("for-profit") && lower.contains("commercial license"),
        "README license section must state the for-profit commercial-license rule"
    );
    assert!(
        lower.contains("anticipated commercial application"),
        "README license section must reflect PolyForm's anticipated-commercial-application scope"
    );
    assert!(
        lower.contains("use-case table"),
        "README license section must point readers to the controlling use-case table"
    );
}
