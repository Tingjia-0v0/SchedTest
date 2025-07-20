// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
)

// String generates a very compact program description (mostly for debug output).
func (p *Prog) String() string {
	buf := new(bytes.Buffer)
	for i, c := range p.Calls {
		if i != 0 {
			fmt.Fprintf(buf, "-")
		}
		fmt.Fprintf(buf, "%v", c.Meta.Name)
	}
	return buf.String()
}

func (p *Prog) Serialize() []byte {
	return p.serialize(false)
}

func (p *Prog) SerializeVerbose() []byte {
	return p.serialize(true)
}

func (p *Prog) serialize(verbose bool) []byte {
	p.debugValidate()
	ctx := &serializer{
		target:  p.Target,
		buf:     new(bytes.Buffer),
		vars:    make(map[*ResultArg]int),
		verbose: verbose,
	}
	for _, c := range p.Calls {
		ctx.call(c)
	}
	return ctx.buf.Bytes()
}

type serializer struct {
	target  *Target
	buf     *bytes.Buffer
	vars    map[*ResultArg]int
	varSeq  int
	verbose bool
}

func (ctx *serializer) print(text string) {
	ctx.printf("%v", text)
}

func (ctx *serializer) printf(text string, args ...interface{}) {
	fmt.Fprintf(ctx.buf, text, args...)
}

func (ctx *serializer) allocVarID(arg *ResultArg) int {
	id := ctx.varSeq
	ctx.varSeq++
	ctx.vars[arg] = id
	return id
}

func (ctx *serializer) call(c *Call) {
	if c.Ret != nil && len(c.Ret.uses) != 0 {
		ctx.printf("r%v = ", ctx.allocVarID(c.Ret))
	}
	ctx.printf("%v(", c.Meta.Name)
	for i, a := range c.Args {
		if IsPad(a.Type()) {
			continue
		}
		if i != 0 {
			ctx.printf(", ")
		}
		ctx.arg(a)
	}
	ctx.print(")")

	anyChangedProps := false
	c.Props.ForeachProp(func(name, key string, value reflect.Value) {
		// reflect.Value.IsZero is added in go1.13, not available in Appengine SDK.
		if reflect.DeepEqual(value.Interface(), reflect.Zero(value.Type()).Interface()) {
			return
		}

		if !anyChangedProps {
			ctx.print(" (")
			anyChangedProps = true
		} else {
			ctx.print(", ")
		}

		ctx.print(key)
		switch kind := value.Kind(); kind {
		case reflect.Int:
			ctx.printf(": %d", value.Int())
		case reflect.Bool:
		default:
			panic("unable to serialize call prop of type " + kind.String())
		}
	})
	if anyChangedProps {
		ctx.printf(")")
	}

	ctx.printf("\n")
}

func (ctx *serializer) arg(arg Arg) {
	if arg == nil {
		ctx.printf("nil")
		return
	}
	arg.serialize(ctx)
}

func (a *ConstArg) serialize(ctx *serializer) {
	ctx.printf("0x%x", a.Val)
}

func (a *PointerArg) serialize(ctx *serializer) {
	if a.IsSpecial() {
		ctx.printf("0x%x", a.Address)
		return
	}
	target := ctx.target
	ctx.printf("&%v", target.serializeAddr(a))
	if a.Res != nil && !ctx.verbose && isDefault(a.Res) && !target.isAnyPtr(a.Type()) {
		return
	}
	ctx.printf("=")
	if target.isAnyPtr(a.Type()) {
		ctx.printf("ANY=")
	}
	ctx.arg(a.Res)
}

func (a *DataArg) serialize(ctx *serializer) {
	typ := a.Type().(*BufferType)
	if a.Dir() == DirOut {
		ctx.printf("\"\"/%v", a.Size())
		return
	}
	data := a.Data()

	// Statically typed data will be padded with 0s during deserialization,
	// so we can strip them here for readability always. For variable-size
	// data we strip trailing 0s only if we strip enough of them.
	sz := len(data)
	for len(data) >= 2 && data[len(data)-1] == 0 && data[len(data)-2] == 0 {
		data = data[:len(data)-1]
	}
	if typ.Varlen() && len(data)+8 >= sz {
		data = data[:sz]
	}
	serializeData(ctx.buf, data, isReadableDataType(typ))
	if typ.Varlen() && sz != len(data) {
		ctx.printf("/%v", sz)
	}

}

func (a *GroupArg) serialize(ctx *serializer) {
	var delims []byte
	switch a.Type().(type) {
	case *StructType:
		delims = []byte{'{', '}'}
	case *ArrayType:
		delims = []byte{'[', ']'}
	default:
		panic("unknown group type")
	}
	ctx.buf.WriteByte(delims[0])
	lastNonDefault := len(a.Inner) - 1
	if !ctx.verbose && a.fixedInnerSize() {
		for ; lastNonDefault >= 0; lastNonDefault-- {
			if !isDefault(a.Inner[lastNonDefault]) {
				break
			}
		}
	}
	for i := 0; i <= lastNonDefault; i++ {
		arg1 := a.Inner[i]
		if arg1 != nil && IsPad(arg1.Type()) {
			continue
		}
		if i != 0 {
			ctx.printf(", ")
		}
		ctx.arg(arg1)
	}
	ctx.buf.WriteByte(delims[1])
}

func (a *UnionArg) serialize(ctx *serializer) {
	typ := a.Type().(*UnionType)
	ctx.printf("@%v", typ.Fields[a.Index].Name)
	if !ctx.verbose && isDefault(a.Option) {
		return
	}
	ctx.printf("=")
	ctx.arg(a.Option)
}

func (a *ResultArg) serialize(ctx *serializer) {
	if len(a.uses) != 0 {
		ctx.printf("<r%v=>", ctx.allocVarID(a))
	}
	if a.Res == nil {
		ctx.printf("0x%x", a.Val)
		return
	}
	id, ok := ctx.vars[a.Res]
	if !ok {
		panic("no result")
	}
	ctx.printf("r%v", id)
	if a.OpDiv != 0 {
		ctx.printf("/%v", a.OpDiv)
	}
	if a.OpAdd != 0 {
		ctx.printf("+%v", a.OpAdd)
	}
}

type DeserializeMode int

const (
	// In strict mode deserialization fails if the program is malformed in any way.
	// This mode is used for manually written programs to ensure that they are correct.
	Strict DeserializeMode = iota
	// In non-strict mode malformed programs silently fixed in a best-effort way,
	// e.g. missing/wrong arguments are replaced with default values.
	// This mode is used for the corpus programs to "repair" them after descriptions changes.
	NonStrict
	// Unsafe mode is used for VM checking programs. In this mode programs are not fixed
	// for safety, e.g. can access global files, issue prohibited ioctl's, disabled syscalls, etc.
	StrictUnsafe
	NonStrictUnsafe
)

const (
	encodingAddrBase = 0x7f0000000000
)

func (target *Target) serializeAddr(arg *PointerArg) string {
	ssize := ""
	if arg.VmaSize != 0 {
		ssize = fmt.Sprintf("/0x%x", arg.VmaSize)
	}
	return fmt.Sprintf("(0x%x%v)", encodingAddrBase+arg.Address, ssize)
}

func serializeData(buf *bytes.Buffer, data []byte, readable bool) {
	if !readable && !isReadableData(data) {
		fmt.Fprintf(buf, "\"%v\"", hex.EncodeToString(data))
		return
	}
	buf.WriteByte('\'')
	encodeData(buf, data, true, false)
	buf.WriteByte('\'')
}

func EncodeData(buf *bytes.Buffer, data []byte, readable bool) {
	if !readable && isReadableData(data) {
		readable = true
	}
	encodeData(buf, data, readable, true)
}

func encodeData(buf *bytes.Buffer, data []byte, readable, cstr bool) {
	for _, v := range data {
		if !readable {
			lo, hi := byteToHex(v)
			buf.Write([]byte{'\\', 'x', hi, lo})
			continue
		}
		switch v {
		case '\a':
			buf.Write([]byte{'\\', 'a'})
		case '\b':
			buf.Write([]byte{'\\', 'b'})
		case '\f':
			buf.Write([]byte{'\\', 'f'})
		case '\n':
			buf.Write([]byte{'\\', 'n'})
		case '\r':
			buf.Write([]byte{'\\', 'r'})
		case '\t':
			buf.Write([]byte{'\\', 't'})
		case '\v':
			buf.Write([]byte{'\\', 'v'})
		case '\'':
			buf.Write([]byte{'\\', '\''})
		case '"':
			buf.Write([]byte{'\\', '"'})
		case '\\':
			buf.Write([]byte{'\\', '\\'})
		default:
			if isPrintable(v) {
				buf.WriteByte(v)
			} else {
				if cstr {
					// We would like to use hex encoding with \x,
					// but C's \x is hard to use: it can contain _any_ number of hex digits
					// (not just 2 or 4), so later non-hex encoded chars will glue to \x.
					c0 := (v>>6)&0x7 + '0'
					c1 := (v>>3)&0x7 + '0'
					c2 := (v>>0)&0x7 + '0'
					buf.Write([]byte{'\\', c0, c1, c2})
				} else {
					lo, hi := byteToHex(v)
					buf.Write([]byte{'\\', 'x', hi, lo})
				}
			}
		}
	}
}

func isReadableDataType(typ *BufferType) bool {
	return typ.Kind == BufferString || typ.Kind == BufferFilename || typ.Kind == BufferGlob
}

func isReadableData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, v := range data {
		if isPrintable(v) {
			continue
		}
		switch v {
		case 0, '\a', '\b', '\f', '\n', '\r', '\t', '\v':
			continue
		}
		return false
	}
	return true
}

func isPrintable(v byte) bool {
	return v >= 0x20 && v < 0x7f
}

func byteToHex(v byte) (lo, hi byte) {
	return toHexChar(v & 0xf), toHexChar(v >> 4)
}

func toHexChar(v byte) byte {
	if v >= 16 {
		panic("bad hex char")
	}
	if v < 10 {
		return '0' + v
	}
	return 'a' + v - 10
}

// CallSet returns a set of all calls in the program.
// It does very conservative parsing and is intended to parse past/future serialization formats.
func CallSet(data []byte) (map[string]struct{}, int, error) {
	calls := make(map[string]struct{})
	ncalls := 0
	for len(data) > 0 {
		ln := data
		nextLine := bytes.IndexByte(data, '\n')
		if nextLine != -1 {
			ln = data[:nextLine]
			data = data[nextLine+1:]
		} else {
			data = nil
		}
		if len(ln) == 0 || ln[0] == '#' {
			continue
		}
		bracket := bytes.IndexByte(ln, '(')
		if bracket == -1 {
			return nil, 0, fmt.Errorf("line does not contain opening bracket")
		}
		call := ln[:bracket]
		if eq := bytes.IndexByte(call, '='); eq != -1 {
			eq++
			for eq < len(call) && call[eq] == ' ' {
				eq++
			}
			call = call[eq:]
		}
		if len(call) == 0 {
			return nil, 0, fmt.Errorf("call name is empty")
		}
		calls[string(call)] = struct{}{}
		ncalls++
	}
	if len(calls) == 0 {
		return nil, 0, fmt.Errorf("program does not contain any calls")
	}
	return calls, ncalls, nil
}
