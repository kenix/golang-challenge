package drum

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// DecodeFile decodes the drum machine file found at the provided path
// and returns a pointer to a parsed pattern which is the entry point to the
// rest of the data.
func DecodeFile(path string) (*Pattern, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	content, err := readAll(f)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(content)
	prtcl := string(buf.Next(6))
	if "SPLICE" != prtcl {
		return nil, fmt.Errorf("want SPLICE, got %s", prtcl)
	}
	var length int64
	if err = binary.Read(buf, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	buf = bytes.NewBuffer(buf.Next(int(length)))
	version := strings.TrimRight(string(buf.Next(32)), "\x00")
	var tempo float32
	if err = binary.Read(buf, binary.LittleEndian, &tempo); err != nil {
		return nil, err
	}

	p := &Pattern{version, tempo, make([]*Track, 0, 0)}
	for buf.Len() > 0 {
		var id int32
		if err = binary.Read(buf, binary.LittleEndian, &id); err != nil {
			return p, err
		}
		c, err := buf.ReadByte()
		if err != nil {
			return p, err
		}
		name := string(buf.Next(int(c)))
		p.addTrack(&Track{id, name, buf.Next(16)})
	}

	return p, nil
}

func readAll(f *os.File) ([]byte, error) {
	defer f.Close()
	cntnt, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return cntnt, nil
}

// Pattern is the high level representation of the
// drum pattern contained in a .splice file.
type Pattern struct {
	version string // 32
	tempo   float32
	tracks  []*Track
}

func (p *Pattern) addTrack(t *Track) {
	p.tracks = append(p.tracks, t)
}

func (p *Pattern) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "Saved with HW Version: %s\n", p.version)
	fmt.Fprintf(buf, "Tempo: %g\n", p.tempo)
	for _, t := range p.tracks {
		fmt.Fprintf(buf, "%s\n", t)
	}
	return buf.String()
}

type Track struct {
	id    int32
	name  string
	steps []byte
}

func (t *Track) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "(%d) %s\t", t.id, t.name)
	for i, s := range t.steps {
		if i%4 == 0 {
			fmt.Fprintf(buf, "|")
		}
		switch s {
		case 0:
			fmt.Fprintf(buf, "-")
		case 1:
			fmt.Fprintf(buf, "x")
		default:
			panic(fmt.Errorf("invalid step value % x", s))
		}
	}
	fmt.Fprintf(buf, "|")
	return buf.String()
}
