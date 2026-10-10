// Package rx compiles configured regular expressions once. Patterns come
// from config (prod patterns, account-name and elevated-role patterns) and
// are matched against every account, role and context a command handles —
// a picker of 200 accounts would otherwise compile the same pattern 200
// times.
package rx

import (
	"regexp"
	"sync"
)

type entry struct {
	re  *regexp.Regexp
	err error
}

var cache sync.Map // pattern → entry

// Compile is regexp.Compile, remembered per pattern (errors included).
func Compile(p string) (*regexp.Regexp, error) {
	if e, ok := cache.Load(p); ok {
		return e.(entry).re, e.(entry).err
	}
	re, err := regexp.Compile(p)
	cache.Store(p, entry{re, err})
	return re, err
}
