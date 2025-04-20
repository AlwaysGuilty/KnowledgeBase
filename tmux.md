# tmux

Useful guides:
- [IppSec's guide](https://www.youtube.com/watch?v=Lqehvpe_djs)
- https://mutelight.org/practical-tmux

Config files:
- local: `~/.tmux.conf`
- global: `/etc/tmux.conf`

My `~/.tmux.conf`:
```
# Prefix key remapping
set -g prefix C-a
unbind C-b
bind C-a send-prefix

# Window numbering
set -g base-index 1
set -g pane-base-index 1
set-window-option -g pane-base-index 1
set -g renumber-windows on

# QoL
set -g history-limit 10000
set -g allow-rename off
set -g mouse
set -g mode-keys vi
set-option -sa terminal-features ',tmux-256color:RGB'

# Plugins
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
#set -g @plugin 'tmux-plugins/tmux-yank' # copy line with 'y' instead of the default 'l'
set -g @plugin 'catppuccin/tmux'

# Catppuccin theme
set -g @catppuccin_flavour 'frappe'

# Other catppuccin settins
set -g @catppuccin_window_number_position "left"
set -g @catppuccin_status_modules_right "host date_time session"
#set -g @catppuccin_directory_text "#{pane_current_path}" # not used
set -g status-position bottom
set -g @catppuccin_window_default_fill "number"
set -g @catppuccin_window_default_text "#W"
set -g @catppuccin_window_current_fill "number"
set -g @catppuccin_window_current_text "#W"

# Initialize TMUX plugin manager
run '~/.tmux/plugins/tpm/tpm'
```

A note on using tmux keybinds: **DO NOT** press they prefix key and the keybind at the same time, it might not work (at least it doesn't work for me). Instead, press the prefix key (C-b or what have you), release it and only press the keybind after that. (https://superuser.com/questions/325110/how-to-turn-down-the-timeout-between-prefix-key-and-command-key-in-tmux)

| Command | Description |
|-|-|
| `tmux` | opens a new unnamed tmux session |
| `tmux new -s <name>` | opens a new named tmux session |
| `tmux ls` | list tmux sessions |
| `tmux attach -t <name>` | attach to a named tmux session |
| `tmux a` | attach to previously opened session |
| `tmux detach` | detach from session |
| `tmux kill-session -t <session>`| kills a specified session |


| Keybind | Description |
|-|-|
| `Ctrl + D` | Detach from the session |
| `(prefix) + ?` | View all keybinds. Press `q` to quit. |
| `(prefix) + C` | new window |
| `(prefix) + "` | horizontal split |
| `(prefix) + %` | vertical split |
| `(prefix) + <arrow key>` | Switch to a pane in specified direction. If pressed at the same time, it adjusts the pane size in the specified direction. |
| `(prefix) + <number>` | switch to corresponding window |
| `(prefix) + d` | detach from current session |
| `(prefix) + x` | exit from the current pane |
| `(prefix) + z` | zoom/unzoom on the pane |
| `(prefix) + :` | Open command line. You can use it to input settings like `set -g mouse` |
| `(prefix) + ,` | open command line to rename the window |
| `(prefix) + [` | Scroll mode: use arrow keys or `PgUp/PgDn` to scroll up/down. Press `q` to quit from scroll mode. |

Copying and pasting text in emacs mode:
1. `(prefix) + [` to enter copy mode
2. navigate to the text you would like to copy
3. `Ctr + Space` to start selection
4. select text with `<arrow keys>`/`PgUp`/`PgDn`/`Home`/`End`
5. `Alt + W` to copy selection and exit from copy mode

Copying and pasting text in vim mode:
1. `(prefix) + [` to enter copy mode
2. navigate to the text you would like to copy
3. `Space` to start selection
4. select text with `<arrow keys>`/`PgUp`/`PgDn`/`w` (go one word forward)/`b` (go one word backwards)/`V` (whole line)/`Home`/`End`
5. `Enter` to copy selection and exit from copy mode

## TPM

https://github.com/tmux-plugins/tpm
