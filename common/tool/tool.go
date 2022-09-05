package tool

import (
	"os"
)

// IsFileExist check if the file path exists
func IsFileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}
