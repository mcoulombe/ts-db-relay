package internal

import "net"

type BufferedConn struct {
	net.Conn
	buffer []byte
	offset int
}

func NewBufferedConn(conn net.Conn, bufferedData ...[]byte) *BufferedConn {
	var totalLen int
	for _, data := range bufferedData {
		totalLen += len(data)
	}

	buffer := make([]byte, 0, totalLen)
	for _, data := range bufferedData {
		buffer = append(buffer, data...)
	}

	return &BufferedConn{
		Conn:   conn,
		buffer: buffer,
		offset: 0,
	}
}

func (bc *BufferedConn) Read(p []byte) (n int, err error) {
	if bc.offset < len(bc.buffer) {
		n = copy(p, bc.buffer[bc.offset:])
		bc.offset += n
		return n, nil
	}
	return bc.Conn.Read(p)
}
