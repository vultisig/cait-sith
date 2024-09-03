// main.go

package main

/*
#cgo LDFLAGS: -L${SRCDIR}/../target/release -Wl,-rpath,${SRCDIR}/../target/release -lcait_sith

int rust_function_add(int a, int b);
*/
import "C"
import (
	"fmt"
)

func main() {
	sum := C.rust_function_add(C.int(4), C.int(5))
	fmt.Printf("The sum of 4 and 5 is: %d\n", int(sum))
}
