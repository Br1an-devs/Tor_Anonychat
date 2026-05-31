# SecureChat — Tor Hidden Service

## How to use

### Before first use — one-time setup (HOST only)

Run these commands once to create your hidden service and get your permanent onion address:

```bash
# 1. Add the hidden service block to Tor config
sudo bash -c 'printf "\n# SecureChat\nHiddenServiceDir /var/lib/tor/securechat\nHiddenServicePort 57311 127.0.0.1:57311\n" >> /etc/tor/instances/default/torrc'

# If /etc/tor/instances/default/torrc does not exist on your system, use this instead:
sudo bash -c 'printf "\n# SecureChat\nHiddenServiceDir /var/lib/tor/securechat\nHiddenServicePort 57311 127.0.0.1:57311\n" >> /etc/tor/torrc'

# 2. Create the hidden service directory with correct ownership
sudo mkdir -p /var/lib/tor/securechat
sudo chown debian-tor:debian-tor /var/lib/tor/securechat
sudo chmod 700 /var/lib/tor/securechat

# 3. Restart the Tor instance
sudo systemctl restart tor@default

# 4. Wait ~15 seconds, then read your onion address
sleep 15 && sudo cat /var/lib/tor/securechat/hostname
```

Your onion address will look like:
`abcdef1234567890abcdef1234567890abcdef1234567890abcdef12.onion`

**Save this address. It is permanent as long as you keep the keys in `/var/lib/tor/securechat/`.**

---

### Get your onion address any time

```bash
sudo cat /var/lib/tor/securechat/hostname
```

Or use **option 3** in the app menu.

---

## Session flow

### HOST
1. Run `bash run_tor.sh`
2. Choose **option 3** to view your onion address (or read it from terminal above)
3. Choose **option 1** — Host a session
4. Paste your onion address when prompted
5. A session code is generated and displayed
6. Send **both** the onion address and session code to your guest via phone call, Signal, or any out-of-band channel
7. Wait for the guest to connect

### GUEST
1. Run `bash run_tor.sh`
2. Choose **option 2** — Join a session
3. Enter the onion address sent by the host
4. Enter the session code sent by the host
5. Connection established

---

## Security notes

- Never share the onion address or session code over unencrypted channels
- The session code is one-time use only
- No logs, no history, no IP addresses leave either machine
- All messages are encrypted with AES-256-GCM
