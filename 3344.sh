#!/bin/bash

SESSION="network"

# Start a new tmux session
tmux new-session -d -s $SESSION

# Create a new window for each command
tmux new-window -n "network_ca_1" "go run . network_ca 1"
tmux new-window -n "network_ca_2" "go run . network_ca 2"
tmux new-window -n "network_ca_3" "go run . network_ca 3"
tmux new-window -n "network_logger_1" "go run . network_logger 1"
tmux new-window -n "network_logger_2" "go run . network_logger 2"
tmux new-window -n "network_logger_3" "go run . network_logger 3"
tmux new-window -n "network_monitor_1" "go run . network_monitor 1"
tmux new-window -n "network_monitor_2" "go run . network_monitor 2"
tmux new-window -n "network_monitor_3" "go run . network_monitor 3"
tmux new-window -n "network_monitor_4" "go run . network_monitor 4"
tmux new-window -n "network_gossiper_1" "go run . network_gossiper 1"
tmux new-window -n "network_gossiper_2" "go run . network_gossiper 2"
tmux new-window -n "network_gossiper_3" "go run . network_gossiper 3"
tmux new-window -n "network_gossiper_4" "go run . network_gossiper 4"

# Attach to the tmux session
tmux attach-session -t $SESSION