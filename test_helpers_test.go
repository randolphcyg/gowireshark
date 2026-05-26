package gowireshark

import "context"

func openSession(path string, opts ...Option) (*Session, error) {
	return OpenSessionContext(context.Background(), path, opts...)
}
