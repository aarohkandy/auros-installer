# Installing the Linux-side restore

Two files go into the image (`auros-base`):

| From | To |
|---|---|
| the `auros-restore` binary | `/usr/libexec/auros/auros-restore` |
| `auros-restore.service` | `/usr/lib/systemd/user/auros-restore.service` |

and one command, in the image build, not at first boot:

```
systemctl --global enable auros-restore.service
```

`--global`, not `--user`. There is no user session during an image build, and a
unit enabled into `/etc/skel` is a unit that silently does not exist for an
account created after the image was made.

## What happens on a machine with no archive

Nothing, visibly. `auros-restore` exits 0, writes no report, shows no pop-up and
writes no stamp. A fresh Auros laptop that was never migrated must not show its
owner a warning about a backup they never made.

Because it writes no stamp, it tries again at the next login — which is the
answer to the most likely real failure in a school: the USB stick was still in
somebody's pocket.

## What is NOT here, and why

**The privileged step that switches the Wi-Fi networks on.**

`auros-restore` runs as the user. It writes each migrated network as a
NetworkManager keyfile with mode 0600 into
`~/.local/share/auros-restore/network/`, and the note on the desktop says in
plain words that they are saved and not yet switched on. Moving them to
`/etc/NetworkManager/system-connections` with root ownership needs root.

A root program that reads files out of a user's home directory is the sharpest
edge in this whole product, and it is not in this branch. Doing it safely means
`O_NOFOLLOW`, an owner check through `syscall.Stat_t`, and a strict allow-list
parser that rebuilds the file rather than copying it — and the first two are
forbidden outside `internal/winenv` and `internal/sysdisk` by
`TestWall_SyscallIsConstantsOnly`, which says in as many words that widening it
is an architecture change to argue for in a pull request of its own.

See `BLOCKED.md` B19. Until then:

- an administrator running `auros-restore` as root writes the keyfiles straight
  into `/etc/NetworkManager/system-connections` (implemented, and the mode is
  read back off the disk before the file is left in place); and
- everyone else gets 0600 files in their home directory and a note that says so.

Nothing anywhere reports Wi-Fi as migrated when it has not been.

**The privileged step that adds the printer queues.** Same shape. `auros-restore`
decides which printers can honestly become a driverless IPP queue, writes the
queue definitions to `~/.local/state/auros-restore/printers.plan` as DATA (never
a script — a script in a home directory that root runs later is a
privilege-escalation hole wearing a convenience costume), and says plainly that
nothing has been added yet.
