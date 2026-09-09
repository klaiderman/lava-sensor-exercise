package probe

import (
	"encoding/binary"
	"time"
)

// POSIX ACL tag values from the on-disk `system.posix_acl_access` format.
const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20

	aclVersion  = 2
	aclEntryLen = 8
	aclHeadLen  = 4
	aclUndefID  = 0xFFFFFFFF
)

// ACLEntry is one decoded access-control entry.
type ACLEntry struct {
	Tag   string `json:"tag"`
	ID    int64  `json:"id,omitempty"`
	Read  bool   `json:"read"`
	Write bool   `json:"write"`
	Exec  bool   `json:"exec"`
}

// ACL is the decoded `system.posix_acl_access` xattr of one path.
//
// The three outcomes are deliberately distinct: Present=false with reason
// ENODATA is a positive answer ("this file has no ACL"), while EACCES or
// EOPNOTSUPP leave the question open (L52).
type ACL struct {
	Path             string     `json:"path"`
	Present          bool       `json:"present"`
	Entries          []ACLEntry `json:"entries,omitempty"`
	GrantsNonOwner   bool       `json:"grants_non_owner_read"`
	NamedPrincipals  int64      `json:"named_principals"`
	Errno            string     `json:"errno,omitempty"`
	Determined       bool       `json:"determined"`
	UndecodableBytes int64      `json:"undecodable_bytes,omitempty"`
}

// ReadACL decodes the POSIX access ACL of a path without executing anything.
//
// `getfacl` is not installed on many hosts and is irrelevant here: the xattr is
// read directly, so a missing utility never turns the ACL question into an
// unknown (L39, L52).
func (r *Reader) ReadACL(p string) (ACL, Observation) {
	start := time.Now()
	acl := ACL{Path: p}
	obs := Observation{Source: p + " [system.posix_acl_access]", Kind: KindFileMetadata}

	raw, err := getxattr(r.full(p), "system.posix_acl_access")
	obs.Elapsed = time.Since(start)
	if err != nil {
		status, errno := Classify(err)
		acl.Errno = errno
		switch errno {
		case "ENODATA", "EOPNOTSUPP", "ENOTSUP":
			// No ACL (or no ACL support): a positive answer, not an unknown.
			acl.Determined = true
			acl.Present = false
			obs.Status = StatusOK
			obs.Value = "no ACL (" + errno + ")"
			obs.Detail = "the file carries no POSIX access ACL"
		default:
			obs.Status = status
			obs.Errno = errno
			obs.Detail = shortErr(err)
		}
		return acl, obs
	}

	obs.Bytes = int64(len(raw))
	if len(raw) < aclHeadLen || binary.LittleEndian.Uint32(raw[:aclHeadLen]) != aclVersion {
		// An unexpected version is not decoded and not guessed at.
		acl.Errno = "EINVAL"
		acl.UndecodableBytes = int64(len(raw))
		obs.Status = StatusUnsupported
		obs.Errno = "EINVAL"
		obs.Detail = "system.posix_acl_access is not version 2; not decoded"
		return acl, obs
	}
	body := raw[aclHeadLen:]
	if len(body)%aclEntryLen != 0 {
		acl.Errno = "EINVAL"
		acl.UndecodableBytes = int64(len(body) % aclEntryLen)
		obs.Status = StatusUnsupported
		obs.Errno = "EINVAL"
		obs.Detail = "system.posix_acl_access body is not a whole number of entries"
		return acl, obs
	}

	acl.Determined = true
	acl.Present = true
	var maskRead = true
	var hasMask bool
	for off := 0; off+aclEntryLen <= len(body); off += aclEntryLen {
		tag := binary.LittleEndian.Uint16(body[off : off+2])
		perm := binary.LittleEndian.Uint16(body[off+2 : off+4])
		id := binary.LittleEndian.Uint32(body[off+4 : off+8])
		e := ACLEntry{
			Tag:   aclTagName(tag),
			Read:  perm&4 != 0,
			Write: perm&2 != 0,
			Exec:  perm&1 != 0,
		}
		if id != aclUndefID {
			e.ID = int64(id)
		}
		if tag == aclMask {
			hasMask, maskRead = true, perm&4 != 0
		}
		acl.Entries = append(acl.Entries, e)
	}
	// A named user or group entry is only effective when the mask allows it.
	for _, e := range acl.Entries {
		switch e.Tag {
		case "user", "group":
			acl.NamedPrincipals++
			if e.Read && (!hasMask || maskRead) {
				acl.GrantsNonOwner = true
			}
		case "other":
			if e.Read {
				acl.GrantsNonOwner = true
			}
		}
	}
	obs.Status = StatusOK
	obs.Value = "ACL with " + itoa(int64(len(acl.Entries))) + " entries"
	return acl, obs
}

func aclTagName(tag uint16) string {
	switch tag {
	case aclUserObj:
		return "user_obj"
	case aclUser:
		return "user"
	case aclGroupObj:
		return "group_obj"
	case aclGroup:
		return "group"
	case aclMask:
		return "mask"
	case aclOther:
		return "other"
	}
	return "unknown"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
