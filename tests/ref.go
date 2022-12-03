package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/cosmos/iavl"
	db "github.com/tendermint/tm-db"
)

const (
	int64Size = 8
	hashSize  = sha256.Size
)

var orphanKeyFormat = iavl.NewKeyFormat('o', int64Size, int64Size, hashSize) // o<last-version><first-version><hash>

func CountOrphans(kvdb db.DB, version int64) int {
	it, err := kvdb.Iterator(orphanKeyFormat.Key(version-1), orphanKeyFormat.Key(version))
	if err != nil {
		panic(err)
	}

	count := 0
	for ; it.Valid(); it.Next() {
		count++
	}
	return count
}

func main() {
	d := db.NewMemDB()
	tree, err := iavl.NewMutableTree(d, 100, true)
	if err != nil {
		panic(err)
	}
	_, err = tree.Set([]byte("hello"), []byte("world"))
	if err != nil {
		panic(err)
	}
	hash, v, err := tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X %d\n", v, hash, CountOrphans(d, tree.Version()))

	_, err = tree.Set([]byte("hello"), []byte("world1"))
	if err != nil {
		panic(err)
	}
	_, err = tree.Set([]byte("hello1"), []byte("world1"))
	if err != nil {
		panic(err)
	}
	hash, v, err = tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X %d\n", v, hash, CountOrphans(d, tree.Version()))

	tree.Set([]byte("hello2"), []byte("world1"))
	tree.Set([]byte("hello3"), []byte("world1"))
	hash, v, err = tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X %d\n", v, hash, CountOrphans(d, tree.Version()))

	for i := 0; i < 20; i++ {
		tree.Set([]byte(fmt.Sprintf("hello%02d", i)), []byte("world1"))
	}
	hash, v, err = tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X %d\n", v, hash, CountOrphans(d, tree.Version()))

	tree.Remove([]byte("hello"))
	tree.Remove([]byte("hello19"))
	hash, v, err = tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X %d\n", v, hash, CountOrphans(d, tree.Version()))

	// try to cover left balancing case
	for i := 0; i <= 20; i++ {
		tree.Set([]byte(fmt.Sprintf("aello%02d", i)), []byte("world1"))
	}
	hash, v, err = tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X %d\n", v, hash, CountOrphans(d, tree.Version()))

	// remove most of the values
	for i := 0; i <= 20; i++ {
		tree.Remove([]byte(fmt.Sprintf("aello%02d", i)))
	}
	for i := 0; i < 19; i++ {
		tree.Remove([]byte(fmt.Sprintf("hello%02d", i)))
	}
	hash, v, err = tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X %d\n", v, hash, CountOrphans(d, tree.Version()))
}
