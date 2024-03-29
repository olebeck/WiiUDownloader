package wiiudownloader

/*
#cgo CFLAGS: -I${SRCDIR}/cdecrypt
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}
#cgo LDFLAGS: -L${SRCDIR}
#cgo LDFLAGS: -lcdecrypt
#include <cdecrypt.h>
#include <ctype.h>
#include <stdlib.h>

// Declare a separate C function that calls the Go function progressCallback
extern void callProgressCallback(int progress);
*/
import "C"
import (
	"errors"
	"unsafe"

	"golang.org/x/sync/errgroup"
)

//export callProgressCallback
func callProgressCallback(progress C.int) {
	progressChan <- int(progress)
}

var progressChan chan int

func DecryptContents(path string, deleteEncryptedContents bool) error {
	progressChan = make(chan int)

	errGroup := errgroup.Group{}

	errGroup.Go(func() error {
		return runDecryption(path, deleteEncryptedContents)
	})

	return errGroup.Wait()
}

func runDecryption(path string, deleteEncryptedContents bool) error {
	defer close(progressChan)
	argv := []*C.char{
		C.CString("WiiUDownloader"),
		C.CString(path),
	}
	defer func() {
		for _, arg := range argv {
			C.free(unsafe.Pointer(arg))
		}
	}()

	// Register the C callback function with C
	C.set_progress_callback(C.ProgressCallback(C.callProgressCallback))

	if int(C.cdecrypt_main(2, (**C.char)(unsafe.Pointer(&argv[0])))) != 0 {
		return errors.New("decryption failed")
	}

	if deleteEncryptedContents {
		doDeleteEncryptedContents(path)
	}

	return nil
}
