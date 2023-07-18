# Made with VHS: https://github.com/charmbracelet/vhs
# VHS documentation
#
# Output:
#   Output <path>.gif               Create a GIF output at the given <path>
#   Output <path>.mp4               Create an MP4 output at the given <path>
#   Output <path>.webm              Create a WebM output at the given <path>
#
# Settings:
#   Set FontSize <number>           Set the font size of the terminal
#   Set FontFamily <string>         Set the font family of the terminal
#   Set Height <number>             Set the height of the terminal
#   Set Width <number>              Set the width of the terminal
#   Set LetterSpacing <float>       Set the font letter spacing (tracking)
#   Set LineHeight <float>          Set the font line height
#   Set Theme <string>              Set the theme of the terminal (JSON)
#   Set Padding <number>            Set the padding of the terminal
#   Set Framerate <number>          Set the framerate of the recording
#   Set PlaybackSpeed <float>       Set the playback speed of the recording
#
# Sleep:
#   Sleep <time>                    Sleep for a set amount of <time> in seconds
#
# Type:
#   Type[@<time>] "<characters>"    Type <characters> into the terminal with a
#                                   <time> delay between each character
#
# Keys:
#   Backspace[@<time>] [number]     Press the Backspace key
#   Down[@<time>] [number]          Press the Down key
#   Enter[@<time>] [number]         Press the Enter key
#   Space[@<time>] [number]         Press the Space key
#   Tab[@<time>] [number]           Press the Tab key
#   Left[@<time>] [number]          Press the Left Arrow key
#   Right[@<time>] [number]         Press the Right Arrow key
#   Up[@<time>] [number]            Press the Up Arrow key
#   Down[@<time>] [number]          Press the Down Arrow key
#   Ctrl+<key>                      Press the Control key + <key> (e.g. Ctrl+C)
#
# Display:
#   Hide                            Hide the subsequent commands from the output
#   Show                            Show the subsequent commands in the output
#
# Run `socat TCP-LISTEN:6000,reuseaddr,fork UNIX-CLIENT:\"$DISPLAY\"` before recording to enable clipboard operations
# If using XQuartz, also run `xhost + localhost`
#
# Postprocess with `ffmpeg -an -i wiretap_demo.mp4 -vf "scale=1600:-1,fps=30" -c:v libx264 -preset slow -crf 28 output.mp4`

Output media/wiretap_demo.mp4

Set FontSize 14
Set Width 1600
Set Height 800
Set TypingSpeed 0.1
Set Padding 20
# Set Framerate 24

# build and setup
Hide
Type "docker compose up --build -d" Enter

Type "tmux" Enter

Type "tmux set -g status off" Enter
Type "tmux setw -g pane-active-border-style 'fg=green'" Enter
Type "tmux setw -g pane-border-style 'fg=green'" Enter

Type "docker exec -it wiretap-client-1 bash" Enter
Type "export PS1='client$ '" Enter
Ctrl+l

# split window
Ctrl+b
Type "%"

Type "docker exec -it wiretap-server-1 bash" Enter
Type "export PS1='server$ '" Enter
Ctrl+l

# switch to client 
Ctrl+b
Left
Show

# end build and setup
Set TypingSpeed 0.3
Sleep 4s

# get machine info
Type "ip a" Sleep 1s Enter Sleep 2s

Ctrl+b
Right
Sleep 2s

Type "ip a" Sleep 1s Enter Sleep 2s
Type "curl http://target" Sleep 1s Enter Sleep 2s
Type "nslookup target" Sleep 1s Enter Sleep 2s

Ctrl+b
Left
Sleep 2s

# show curl doesn't work, then configure wiretap
Type "curl http://10.2.0.4 --connect-timeout 3" Sleep 1s Enter Sleep 6s
Type "./wiretap configure --endpoint 10.1.0.2:51820 --routes 10.2.0.0/16,fd:2::/64 -c" Sleep 1s Enter Sleep 4s
Type "wg-quick up ./wiretap_relay.conf" Sleep 1s Enter Sleep 2s
Type "wg-quick up ./wiretap.conf" Sleep 1s Enter Sleep 2s

Ctrl+b
Left
Sleep 2s

# args are in clipboard now
# this is bash magic, ESC+Ctrl+E will expand the current line
# type $(xsel)
# run expansion to make command line look like it was pasted
Hide
Type "$(xsel)"
Escape
Ctrl+e
Show
Sleep 4s
Enter
Sleep 3s

Ctrl+b
Left
Sleep 2s

Type "wg show" Sleep 1s Enter Sleep 2s
Type "curl http://10.2.0.4" Sleep 1s Enter Sleep 2s

Sleep 5s
# shutdown
Set TypingSpeed 0.1
Hide
Ctrl+b
Type ":kill-session"
Enter

Type "docker-compose down -t 1" Enter
Sleep 5s
# end shutdown
