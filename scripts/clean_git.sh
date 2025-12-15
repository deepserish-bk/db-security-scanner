#!/bin/bash
echo "Cleaning Git repository..."

# Remove files from Git that are now ignored
git rm --cached `git ls-files -i --exclude-from=.gitignore` 2>/dev/null || true

# Remove empty directories
find . -type d -empty -delete

echo "Done!"
