// main.go

package main

import "C"
import (
	"fmt"
	"unsafe"
)

func main() {
	name := C.CString("World")
	defer C.free(unsafe.Pointer(name))

	result := C.greet(name)
	defer C.free_string(result)

	goResult := C.GoString(result)
	fmt.Println(goResult)
}
