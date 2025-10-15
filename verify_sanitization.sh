#!/bin/bash
# Verification script to check for sensitive data before pushing to GitHub

echo "🔍 Verifying sanitization of pineapple-express-public..."
echo ""

ISSUES_FOUND=0

# Check for hardcoded user paths
echo "1️⃣ Checking for hardcoded user paths..."
if grep -r "flowgirl" . --exclude-dir=.git --exclude="*.md" --exclude="verify_sanitization.sh" -q; then
    echo "   ❌ Found 'flowgirl' references:"
    grep -r "flowgirl" . --exclude-dir=.git --exclude="*.md" --exclude="verify_sanitization.sh"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo "   ✅ No 'flowgirl' references found"
fi

# Check for personal network names
echo ""
echo "2️⃣ Checking for personal network names..."
if grep -r "RoomForSaints" . --exclude-dir=.git --exclude="*.md" --exclude="verify_sanitization.sh" -q; then
    echo "   ❌ Found 'RoomForSaints' references:"
    grep -r "RoomForSaints" . --exclude-dir=.git --exclude="*.md" --exclude="verify_sanitization.sh"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo "   ✅ No personal network names found"
fi

# Check for API keys or secrets
echo ""
echo "3️⃣ Checking for potential API keys or secrets..."
if grep -rE "(api_key|API_KEY|secret|SECRET|password|PASSWORD|token|TOKEN).*=.*['\"][a-zA-Z0-9]{20,}" . --exclude-dir=.git --exclude="*.md" --exclude="verify_sanitization.sh" -q; then
    echo "   ⚠️ Found potential secrets (review manually):"
    grep -rE "(api_key|API_KEY|secret|SECRET|password|PASSWORD|token|TOKEN).*=.*['\"][a-zA-Z0-9]{20,}" . --exclude-dir=.git --exclude="*.md" --exclude="verify_sanitization.sh"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo "   ✅ No obvious secrets found"
fi

# Check for large files
echo ""
echo "4️⃣ Checking for large files (>10MB)..."
LARGE_FILES=$(find . -type f -size +10M -not -path "./.git/*")
if [ -n "$LARGE_FILES" ]; then
    echo "   ⚠️ Large files found:"
    echo "$LARGE_FILES" | while read file; do
        SIZE=$(du -h "$file" | cut -f1)
        echo "      $SIZE - $file"
    done
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
else
    echo "   ✅ No large files found"
fi

# Check for executable permissions
echo ""
echo "5️⃣ Checking executable permissions on scripts..."
MISSING_EXEC=0
for script in $(find . -name "*.sh" -o -name "*.command"); do
    if [ ! -x "$script" ]; then
        if [ $MISSING_EXEC -eq 0 ]; then
            echo "   ⚠️ Scripts missing executable permission:"
        fi
        echo "      $script"
        MISSING_EXEC=$((MISSING_EXEC + 1))
    fi
done
if [ $MISSING_EXEC -eq 0 ]; then
    echo "   ✅ All scripts have executable permissions"
else
    echo "   💡 Run: find . -name '*.sh' -exec chmod +x {} \\;"
fi

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $ISSUES_FOUND -eq 0 ]; then
    echo "✅ VERIFICATION PASSED - Ready to push!"
    echo ""
    echo "Next steps:"
    echo "  cd /Users/meep/Documents/GithubCheck/pineapple-express-public"
    echo "  git add ."
    echo "  git commit -m 'Complete working version with StealthShark + LoopbackShark'"
    echo "  git push -f origin main"
else
    echo "⚠️ ISSUES FOUND: $ISSUES_FOUND"
    echo "Please review and fix the issues above before pushing."
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
