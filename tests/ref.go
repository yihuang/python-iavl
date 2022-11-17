package main

import (
	"fmt"

	"github.com/cosmos/iavl"
	db "github.com/tendermint/tm-db"
)

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
	fmt.Printf("%d %X\n", v, hash)

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
	fmt.Printf("%d %X\n", v, hash)

	tree.Set([]byte("hello2"), []byte("world1"))
	tree.Set([]byte("hello3"), []byte("world1"))
	hash, v, err = tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X\n", v, hash)

	for i := 0; i < 20; i++ {
		tree.Set([]byte(fmt.Sprintf("hello%02d", i)), []byte("world1"))
	}
	hash, v, err = tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X\n", v, hash)

	tree.Remove([]byte("hello"))
	tree.Remove([]byte("hello19"))
	hash, v, err = tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X\n", v, hash)

	// try to cover left balancing case
	for i := 0; i <= 10; i++ {
		tree.Set([]byte(fmt.Sprintf("aello%02d", i)), []byte("world1"))
	}
	for i := 20; i > 10; i-- {
		tree.Set([]byte(fmt.Sprintf("aello%02d", i)), []byte("world1"))
	}
	hash, v, err = tree.SaveVersion()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d %X\n", v, hash)

}
