/*
    QuarkDash Keystream Implementation

    @git             https://github.com/devsdaddy/quarkdash-go
    @version         1.2.1
    @author          Elijah Rastorguev
    @build           1023
    @website         https://dev.to/devsdaddy
    @updated         28.08.2026
*/
package cipher

// Keystream an interface for lazy keystream with seek and cache
// Used to get a slices from keystream without generation of all stream
type Keystream interface {
	GetBytes(offset, length int) []byte
	Xor(data []byte, keystreamOffset int) []byte
	XorInto(input, output []byte, keystreamOffset int)
	Blocks(startBlock int) func(yield func([]byte) bool)
	Seek(byteOffset int)
	Tell() int
	Rewind()
	Read(length int) []byte
	XorRead(data []byte) []byte
	ClearCache()
	SetCacheLimit(n int)
	BlockSize() int
}

// lazyKeystream - basic implementation with LRU-cache of last 64 blocks.
// Generates blocks by request using gen function
type lazyKeystream struct {
	blockSize    int
	position     int                            // pointer for Read/XorRead
	cachedBlocks map[int][]byte
	maxCache     int
	gen          func(blockIndex int) []byte
}

// newLazyKeystream creates a lazy keystream with block size.
func newLazyKeystream(blockSize int, gen func(int) []byte) *lazyKeystream {
	return &lazyKeystream{
		blockSize:    blockSize,
		cachedBlocks: make(map[int][]byte),
		maxCache:     64,
		gen:          gen,
	}
}

// BlockSize returns a size of one keystream block
func (l *lazyKeystream) BlockSize() int { return l.blockSize }

// getBlock returns block by id, using cache
func (l *lazyKeystream) getBlock(idx int) []byte {
	if c, ok := l.cachedBlocks[idx]; ok {
		return c
	}
	b := l.gen(idx)
	if len(l.cachedBlocks) >= l.maxCache {
		for k := range l.cachedBlocks {
			delete(l.cachedBlocks, k)
			break
		}
	}
	l.cachedBlocks[idx] = b
	return b
}

// GetBytes returns length bytes keystream starting from offset
func (l *lazyKeystream) GetBytes(offset, length int) []byte {
	if offset < 0 || length < 0 {
		panic("invalid offset/length")
	}
	out := make([]byte, length)
	remaining := length
	outPos := 0
	cur := offset
	for remaining > 0 {
		blockIdx := cur / l.blockSize
		off := cur % l.blockSize
		block := l.getBlock(blockIdx)
		take := l.blockSize - off
		if take > remaining {
			take = remaining
		}
		copy(out[outPos:outPos+take], block[off:off+take])
		outPos += take
		cur += take
		remaining -= take
	}
	return out
}

// Xor compute XOR for data with keystream starting from keystreamOffset
func (l *lazyKeystream) Xor(data []byte, keystreamOffset int) []byte {
	out := make([]byte, len(data))
	l.XorInto(data, out, keystreamOffset)
	return out
}

// XorInto compute XOR without garbage allocations: input ^ keystream -> output
func (l *lazyKeystream) XorInto(input, output []byte, keystreamOffset int) {
	if len(output) < len(input) {
		panic("output buffer too small")
	}
	remaining := len(input)
	inPos := 0
	ksPos := keystreamOffset
	for remaining > 0 {
		blockIdx := ksPos / l.blockSize
		off := ksPos % l.blockSize
		block := l.getBlock(blockIdx)
		take := l.blockSize - off
		if take > remaining {
			take = remaining
		}
		for i := 0; i < take; i++ {
			output[inPos+i] = input[inPos+i] ^ block[off+i]
		}
		inPos += take
		ksPos += take
		remaining -= take
	}
}

// Blocks returns an iterator by keystream blocks starts with startBlock (Go 1.23 range).
func (l *lazyKeystream) Blocks(startBlock int) func(yield func([]byte) bool) {
	return func(yield func([]byte) bool) {
		idx := startBlock
		for {
			if !yield(l.getBlock(idx)) {
				return
			}
			idx++
		}
	}
}

// Seek set a pointer (position) in the stream
func (l *lazyKeystream) Seek(byteOffset int) {
	if byteOffset < 0 {
		panic("negative seek")
	}
	l.position = byteOffset
}

// Tell returns current position of the pointer in the stream
func (l *lazyKeystream) Tell() int { return l.position }

// Rewind reset pointer to start
func (l *lazyKeystream) Rewind() { l.position = 0 }

// Read reads length bytes from current position (pointer) and move pointer
func (l *lazyKeystream) Read(length int) []byte {
	out := l.GetBytes(l.position, length)
	l.position += length
	return out
}

// XorRead compute XOR from current position and move pointer
func (l *lazyKeystream) XorRead(data []byte) []byte {
	out := l.Xor(data, l.position)
	l.position += len(data)
	return out
}

// ClearCache clear blocks cache
func (l *lazyKeystream) ClearCache() { l.cachedBlocks = make(map[int][]byte) }

// SetCacheLimit set limit to the blocks cache
func (l *lazyKeystream) SetCacheLimit(n int) { l.maxCache = n }
