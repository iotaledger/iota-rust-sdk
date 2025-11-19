#!/usr/bin/env bash
set -euo pipefail

# Usage: bump_semver <version> <bump_type>
# Examples:
#   bump_semver "1.0.0" "major"    # -> "2.0.0"
#   bump_semver "1.2.3" "minor"    # -> "1.3.0"
#   bump_semver "1.2.3" "patch"    # -> "1.2.4"
#   bump_semver "1.2.3-alpha.1" "release"  # -> "1.2.3"
#   bump_semver "1.0.0" "alpha"    # -> "1.0.1-alpha.1"
#   bump_semver "1.2.3" "beta"     # -> "1.2.4-beta.1"
#   bump_semver "1.2.3" "rc"       # -> "1.2.4-rc.1"
#
# Full usage example:
#   source ./bump_version.sh
#   LATEST="1.0.0-alpha.1"
#   BUMP="alpha"
#   NEW=$(bump_semver "$LATEST" "$BUMP")
#   echo "$NEW"

bump_semver() {
    local version="$1"
    local bump="$2"

    # Remove leading 'v' if present
    version="${version#v}"

    # Parse version into components
    local major minor patch pre_tag pre_num
    if ! parse_version "$version" major minor patch pre_tag pre_num; then
        echo "Invalid semver: $version" >&2
        return 1
    fi

    case "$bump" in
        major)
            echo "$((major + 1)).0.0"
            ;;
        minor)
            echo "$major.$((minor + 1)).0"
            ;;
        patch)
            echo "$major.$minor.$((patch + 1))"
            ;;
        release)
            # Remove prerelease tag to create stable release
            echo "$major.$minor.$patch"
            ;;
        alpha|beta|rc)
            handle_prerelease "$major" "$minor" "$patch" "$pre_tag" "$pre_num" "$bump"
            ;;
        *)
            echo "Unknown bump type: $bump" >&2
            return 1
            ;;
    esac
}

parse_version() {
    local version="$1"
    local -n major_ref="$2" minor_ref="$3" patch_ref="$4" pre_tag_ref="$5" pre_num_ref="$6"

    if [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-(.+))?$ ]]; then
        major_ref="${BASH_REMATCH[1]}"
        minor_ref="${BASH_REMATCH[2]}"
        patch_ref="${BASH_REMATCH[3]}"
        local pre="${BASH_REMATCH[5]:-}"

        if [[ -n "$pre" ]]; then
            if [[ "$pre" =~ ^([a-zA-Z-]+)\.([0-9]+)$ ]]; then
                pre_tag_ref="${BASH_REMATCH[1]}"
                pre_num_ref="${BASH_REMATCH[2]}"
            else
                echo "Invalid prerelease format: $pre" >&2
                return 1
            fi
        else
            pre_tag_ref=""
            pre_num_ref="0"
        fi
        return 0
    else
        return 1
    fi
}

handle_prerelease() {
    local major="$1" minor="$2" patch="$3" current_tag="$4" current_num="$5" desired_tag="$6"
    local sem="$major.$minor.$patch"

    if [[ -z "$current_tag" ]]; then
        # No current prerelease: bump patch and start new prerelease
        echo "$major.$minor.$((patch + 1))-$desired_tag.1"
        return
    fi

    # Precedence order: alpha < beta < rc
    local current_order=0 desired_order=0
    case "$current_tag" in
        alpha) current_order=1 ;;
        beta)  current_order=2 ;;
        rc)    current_order=3 ;;
    esac
    case "$desired_tag" in
        alpha) desired_order=1 ;;
        beta)  desired_order=2 ;;
        rc)    desired_order=3 ;;
    esac

    if [[ "$current_tag" == "$desired_tag" ]]; then
        # Same tag: increment number
        echo "$sem-$desired_tag.$((current_num + 1))"
    elif (( desired_order > current_order )); then
        # Desired tag is later: keep version, start at .1
        echo "$sem-$desired_tag.1"
    else
        # Desired tag is earlier: bump patch, start at .1
        echo "$major.$minor.$((patch + 1))-$desired_tag.1"
    fi
}


main() {
    # Test cases for version bumping
    test_bump_semver() {
        local version="$1"
        local bump="$2"
        local expected="$3"
        local result
        result=$(bump_semver "$version" "$bump")
        if [[ "$result" == "$expected" ]]; then
            echo "✓ PASS: bump_semver '$version' '$bump' -> '$result'"
        else
            echo "✗ FAIL: bump_semver '$version' '$bump' expected '$expected', got '$result'"
            return 1
        fi
    }

    echo ""
    echo "Running test cases..."

    # Test major bumps
    test_bump_semver "1.0.0" "major" "2.0.0"
    test_bump_semver "1.2.3" "major" "2.0.0"
    test_bump_semver "1.2.3-alpha.1" "major" "2.0.0"
    test_bump_semver "1.2.3-beta.2" "major" "2.0.0"
    test_bump_semver "1.2.3-rc.5" "major" "2.0.0"

    # Test minor bumps
    test_bump_semver "1.0.0" "minor" "1.1.0"
    test_bump_semver "1.2.3" "minor" "1.3.0"
    test_bump_semver "1.2.3-alpha.1" "minor" "1.3.0"
    test_bump_semver "1.2.3-beta.2" "minor" "1.3.0"
    test_bump_semver "1.2.3-rc.5" "minor" "1.3.0"

    # Test patch bumps
    test_bump_semver "1.0.0" "patch" "1.0.1"
    test_bump_semver "1.2.3" "patch" "1.2.4"
    test_bump_semver "1.2.3-alpha.1" "patch" "1.2.4"
    test_bump_semver "1.2.3-beta.2" "patch" "1.2.4"
    test_bump_semver "1.2.3-rc.5" "patch" "1.2.4"

    # Test release bumps (remove prerelease)
    test_bump_semver "1.0.0-alpha.1" "release" "1.0.0"
    test_bump_semver "1.2.3-beta.2" "release" "1.2.3"
    test_bump_semver "1.2.3-rc.5" "release" "1.2.3"
    test_bump_semver "2.0.0-alpha.10" "release" "2.0.0"
    test_bump_semver "1.0.0" "release" "1.0.0"  # Already stable, should stay the same

    # Test alpha bumps
    test_bump_semver "1.0.0" "alpha" "1.0.1-alpha.1"
    test_bump_semver "1.2.3" "alpha" "1.2.4-alpha.1"
    test_bump_semver "1.2.3-alpha.1" "alpha" "1.2.3-alpha.2"
    test_bump_semver "1.2.3-beta.2" "alpha" "1.2.4-alpha.1"
    test_bump_semver "1.2.3-rc.5" "alpha" "1.2.4-alpha.1"

    # Test beta bumps
    test_bump_semver "1.0.0" "beta" "1.0.1-beta.1"
    test_bump_semver "1.2.3" "beta" "1.2.4-beta.1"
    test_bump_semver "1.2.3-alpha.1" "beta" "1.2.3-beta.1"
    test_bump_semver "1.2.3-beta.2" "beta" "1.2.3-beta.3"
    test_bump_semver "1.2.3-rc.5" "beta" "1.2.4-beta.1"

    # Test rc (release candidate) bumps
    test_bump_semver "1.0.0" "rc" "1.0.1-rc.1"
    test_bump_semver "1.2.3" "rc" "1.2.4-rc.1"
    test_bump_semver "1.2.3-alpha.1" "rc" "1.2.3-rc.1"
    test_bump_semver "1.2.3-beta.2" "rc" "1.2.3-rc.1"
    test_bump_semver "1.2.3-rc.5" "rc" "1.2.3-rc.6"

    echo "Test cases completed."
}

# Only run tests if this script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi
