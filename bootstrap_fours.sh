#!/usr/bin/env bash

# Abort on error
set -euo pipefail

USERNAME="arvonit"
EXPERIMENT="fours"
GITHUB_REPO="Arvonit/ctng"

# Clone CTng repo to /proj/PKIsec/dev
if [ -d "/proj/PKIsec/dev/ctng" ]
then
    echo "Found CTng repo: Fetching latest changes"
    cd /proj/PKIsec/dev/ctng
    git pull
    cd -
else
    echo "CTng repo not found: Cloning repo to /proj/PKIsec/dev/ctng"
    git clone "https://www.github.com/$GITHUB_REPO.git" /proj/PKIsec/dev/ctng
fi

# cp /proj/PKIsec/dev/ctng ~/ctng

# NOTE: Each node has the same home folder, so copying to one (or the users server) will copy
# to all 
# Determine what to do about this

# Run CTng on each node
node_types=("monitor" "gossiper" "logger" "ca")
for val in ${node_types[@]}
do
    for num in {1..4}
    do
        node="$val-$num"
        address="$USERNAME@$node.$EXPERIMENT.PKIsec"
        # scp -r /proj/PKIsec/dev/ctng "$address:~/ctng"
        ssh $address "cd /proj/PKIsec/dev/ctng && go run ./deterlab $val $num &"
    done
done
