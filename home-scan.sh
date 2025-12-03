#!/bin/bash

# Configuration
SEARCH_DIR="${1:-$HOME}"  # Allow user to specify directory, default to $HOME
EXCLUDE_DIRS=(".cache" ".local" ".config" "snap" ".snap" ".npm" ".docker" "Library" "node_modules" "vendor" ".gradle" ".m2")
MAX_DEPTH=10  # Prevent infinite recursion
COUNT=0

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
    echo "Searching for git repositories in $SEARCH_DIR..."
    echo "=============================================="
    
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
        fi
    done < <(find "$SEARCH_DIR" \
        -maxdepth $MAX_DEPTH \
        -type d \
        -name ".git" \
        -not -path "*/.*/*" 2>/dev/null)
    
    echo "=============================================="
    echo "Found $COUNT git repositories."
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
    # Check if directory exists
    if [ ! -d "$SEARCH_DIR" ]; then
        echo "Error: Directory '$SEARCH_DIR' does not exist."
        exit 1
    fi
    
    # Choose which method to use
    if command -v find >/dev/null 2>&1; then
        # Use find method (faster)
        find_git_repos_find
    else
        # Fall back to manual method
        echo "Searching for git repositories in $SEARCH_DIR..."
        echo "=============================================="
        find_git_repos_manual "$SEARCH_DIR" 0
        echo "=============================================="
        echo "Found $COUNT git repositories."
    fi
}

# Run main function
main