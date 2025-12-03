#!/bin/bash

# Configuration
SEARCH_DIR="${1:-$HOME}"  # Allow user to specify directory, default to $HOME
EXCLUDE_DIRS=(".cache" ".local" ".config" "snap" ".snap" ".npm" ".docker" "Library" "node_modules" "vendor" ".gradle" ".m2")
MAX_DEPTH=10  # Prevent infinite recursion
COUNT=0
declare -a SCAN_DIRS

# Function to check if a directory should be excluded
should_exclude() {
    local dir="$1"
    local dir_name="$(basename "$dir")"
    
    # Exclude hidden directories (except . and ..)
    if [[ "$dir_name" == .* && "$dir" != "$HOME" && "$dir_name" != "." && "$dir_name" != ".." ]]; then
        return 0  # True - should exclude
    fi
    
    # Check against exclusion list
    for exclude in "${EXCLUDE_DIRS[@]}"; do
        if [[ "$dir_name" == "$exclude" ]]; then
            return 0  # True - should exclude
        fi
    done
    
    return 1  # False - should not exclude
}

# Function to find git repositories using find command (more efficient)
find_git_repos_find() {
    echo "== Searching for git repositories in $SEARCH_DIR..."
    echo "=============================================="
    
    local -n scan_dirs="$1"  # nameref to array
    scan_dirs=()  # Clear array
    # Use find command with pruning for better performance
    # found_dir=$(find "$SEARCH_DIR" \
    #     -maxdepth $MAX_DEPTH \
    #     -type d \
    #     -name ".git" \
    #     -not -path "*/.*/*" 2>/dev/null)
    while read git_dir; do
        repo_dir="$(dirname "$git_dir")"
        # Check if we should exclude this directory based on parent path
        exclude_it=0
        for exclude in "${EXCLUDE_DIRS[@]}"; do
            if [[ "$repo_dir" == *"/$exclude"* ]]; then
                exclude_it=1
                break
            fi
        done
        
        if [ $exclude_it -eq 0 ]; then
            ((COUNT++))
            echo "[$COUNT] $repo_dir"
            scan_dirs+=("$repo_dir")
        fi
    done < <(find "$SEARCH_DIR" \
        -maxdepth $MAX_DEPTH \
        -type d \
        -name ".git" \
        -not -path "*/.*/*" 2>/dev/null)
    
    echo "=============================================="
    echo "== Found $COUNT git repositories. =="

}

# Function to find git repositories recursively (manual method)
find_git_repos_manual() {
    local current_dir="$1"
    local depth="$2"
    
    # Check depth limit
    if [ "$depth" -gt "$MAX_DEPTH" ]; then
        return
    fi
    
    # Skip excluded directories
    if should_exclude "$current_dir"; then
        return
    fi
    
    # Check if current directory is a git repository
    if [ -d "$current_dir/.git" ]; then
        echo "[$((++COUNT))] $current_dir"
        return  # Don't go deeper into this directory
    fi
    
    # Iterate through directories
    if [ -d "$current_dir" ] && [ -r "$current_dir" ]; then
        for item in "$current_dir"/*; do
            # Skip if no items match the pattern or if it's not a directory
            [ -e "$item" ] || continue
            [ -d "$item" ] || continue
            [ -L "$item" ] && continue  # Skip symlinks
            
            find_git_repos_manual "$item" "$((depth + 1))"
        done
    fi
}

# Main script execution
main() {
    declare vuln_repos

    # Check if directory exists
    if [ ! -d "$SEARCH_DIR" ]; then
        echo "Error: Directory '$SEARCH_DIR' does not exist."
        exit 1
    fi
    
    mkdir -p $SEARCH_DIR/shai-detector-output

    # Choose which method to use
    if command -v find >/dev/null 2>&1; then
        # Use find method (faster)
        find_git_repos_find SCAN_DIRS
    else
        # Fall back to manual method
        echo "Searching for git repositories in $SEARCH_DIR..."
        echo "=============================================="
        find_git_repos_manual "$SEARCH_DIR" 0
        echo "=============================================="
        echo "Found $COUNT git repositories."
    fi

    echo "Scanning each repo..."
    for repo_path in "${SCAN_DIRS[@]}"; do
        repo=$(basename "$repo_path")
        output="$SEARCH_DIR/shai-detector-output/$repo.out.txt"
        ./shai-hulud-detector.sh "$repo_path" | tee "$output"
        # Use exit code to check presence
        if grep -q "No indicators of Shai-Hulud compromise detected" "$output"; then
            echo "✅ $repo"
        else
            echo "❌😳 Problems detected in $repo_path. Please investigate."
            vuln_repos+=("$repo_path")
        fi
    done

    # cleanup
    rm shai-hulud-detector.tmp.txt

    echo "Potentially impacted repos"
    printf "%s\n" "${vuln_repos[@]}"
}

# Run main function
main