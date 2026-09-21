package restore

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
)

// Ownership is the account every file and directory this run creates must end
// up belonging to.
//
// It exists because a restore started by an administrator — which the systemd
// unit anticipates, since installing NetworkManager keyfiles into /etc needs
// root — writes into somebody else's home directory. Without this, every 0600
// file (the whole Firefox profile, the browser history) ends up owned by root
// inside a home owned by uid 1000: unreadable by the person it belongs to,
// while the report and the re-check both pass because root can read everything
// back.
type Ownership struct {
	UID, GID int
	// chown is os.Lchown in production. It is a field so a test can record the
	// calls on a machine that is not root, which is the only way this check can
	// be watched failing on an ordinary developer's laptop.
	chown func(path string, uid, gid int) error
}

// Apply gives path to the account. It is a no-op when o is nil, which is the
// ordinary case: a run as the owner of the home directory has nothing to do.
//
// Lchown, not Chown: the target is never followed. If a symlink is somehow at
// the path, changing the link's own ownership is harmless and following it is
// not.
func (o *Ownership) Apply(path string) error {
	if o == nil {
		return nil
	}
	fn := o.chown
	if fn == nil {
		fn = os.Lchown
	}
	if err := fn(path, o.UID, o.GID); err != nil {
		return fmt.Errorf("giving %s to uid %d: %w", path, o.UID, err)
	}
	return nil
}

// ApplyTree gives root and everything under it to the account. It does not
// follow links. A no-op when o is nil.
func (o *Ownership) ApplyTree(root string) error {
	if o == nil {
		return nil
	}
	return filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return o.Apply(p)
	})
}

// OwnershipFor is ownershipFor for the command: the state directory, the log and
// the stamp it creates in the home directory under a root run have to be handed
// over too, or the user's own next login cannot write them and the restore runs
// again at every login forever.
func OwnershipFor(home string) (*Ownership, error) { return ownershipFor(home, os.Geteuid()) }

// ownershipFor decides whether this run has to hand its work to somebody else.
//
// Only a run as uid 0 can, and only a run as uid 0 needs to: chown to a
// different uid is a privileged operation, so an ordinary user's run both
// cannot and must not try. euid is a parameter rather than a call to
// os.Geteuid so the decision can be driven from a test at any privilege.
func ownershipFor(home string, euid int) (*Ownership, error) {
	if euid != 0 {
		return nil, nil
	}
	st, err := os.Stat(home)
	if err != nil {
		return nil, fmt.Errorf("restore: cannot tell who owns %s: %w", home, err)
	}
	own, ok := ownerOf(st)
	if !ok {
		// Said out loud rather than assumed. A filesystem with no owners under
		// a root run is not something to guess at.
		return nil, fmt.Errorf("restore: running as root, and this filesystem does not report "+
			"who owns %s, so there is no way to hand the restored files to them", home)
	}
	if own.uid == 0 && own.gid == 0 {
		// root restoring into root's own home. Nothing to hand over.
		return nil, nil
	}
	return &Ownership{UID: own.uid, GID: own.gid}, nil
}

// fileOwner is the numeric owner of one path.
type fileOwner struct{ uid, gid int }

// ownerOf reads the owner out of an os.FileInfo.
//
// It goes through reflect rather than asserting info.Sys().(*syscall.Stat_t),
// and the reason is a rule rather than a preference: internal/safety's
// TestWall_SyscallIsConstantsOnly allows the syscall package outside
// internal/winenv and internal/sysdisk only for errno and signal constants,
// because syscall.NewLazyDLL is the capability the wall exists to deny.
// syscall.Stat_t is inert data and would be harmless — but widening a safety
// wall for the convenience of one package is how walls stop meaning anything,
// and reading two integer fields out of a value the standard library already
// handed us acquires nothing.
//
// When the fields are not there — Windows, a filesystem with no owners — this
// returns false and says nothing further. It never guesses a uid.
func ownerOf(info os.FileInfo) (fileOwner, bool) {
	sys := info.Sys()
	if sys == nil {
		return fileOwner{}, false
	}
	v := reflect.ValueOf(sys)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return fileOwner{}, false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fileOwner{}, false
	}
	uid, uok := uintField(v, "Uid")
	gid, gok := uintField(v, "Gid")
	if !uok || !gok {
		return fileOwner{}, false
	}
	return fileOwner{uid: uid, gid: gid}, true
}

func uintField(v reflect.Value, name string) (int, bool) {
	f := v.FieldByName(name)
	if !f.IsValid() {
		return 0, false
	}
	switch f.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int(f.Uint()), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(f.Int()), true
	default:
		return 0, false
	}
}

// MkdirAllOwned is os.MkdirAll that hands every directory it creates to own,
// and leaves every directory that already existed alone. For the command's own
// state directory, so a root run does not leave ~/.local/state owned by root.
func MkdirAllOwned(dir string, mode os.FileMode, own *Ownership) error {
	return mkdirAllOwned(dir, mode, own)
}
