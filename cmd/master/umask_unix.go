//go:build !windows

package main

import "syscall"

// restrictUmask makes every file the master creates (SQLite DB + WAL/SHM journals, JWT key) private to its owner:
// the database holds node tokens, tunnel secrets and password hashes.
func restrictUmask() { syscall.Umask(0o077) }
