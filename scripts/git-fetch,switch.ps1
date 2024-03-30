param (
	$repo   = 'fork',
	$branch = 'chunker-debugging'
)

echo ''
echo "repo   = $repo"
echo "branch = $branch"
echo ''

Set-PSDebug -Trace 2

git fetch           "$repo"
# Exit non-zero when branch was force updated


git switch --detach "$repo/$branch"

git branch -f             "$branch" "$repo/$branch"

git switch                "$branch"

Set-PSDebug -Off
