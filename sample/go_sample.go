package main

import "fmt"

func hiddenFunc(x int) int {
	return x
}

func helloWorld(x int) int{
	return x+1
}

func GOga_recovered_me(x int) int{
	return x+2
}

func main() {
	a := hiddenFunc(1)
	b := helloWorld(a)
	c := GOga_recovered_me(b)
	fmt.Println(c)
}