package main

import (
	//	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	//	"image/jpeg"
	//	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

type reader func([]byte) reader
type completion func(Tuple) reader

func splittymap(terms []string, sep string) Tuple {
	out := make(Tuple)
	for _, i := range terms {
		x := strings.Split(i, sep)
		out[x[0]] = x[1]
	}
	return out
}

func mmd5(terms ...interface{}) string {
	var inter []byte
	first := true
	for _, i := range terms {
		if !first {
			inter = append(inter, byte(':'))
		}
		first = false
		inter = append(inter, []byte(i.(string))...)
	}
	arr := md5.Sum(inter)
	return hex.EncodeToString(arr[:])
}

func assemble(guys Tuple, sep string, tag string) string {
	dest := ""
	first := true
	for k, v := range guys {
		if !first {
			dest += sep
		}
		first = false
		// bastards
		dest += k + tag + `"` + v.(string) + `"`
	}
	return dest
}

func (s *server) authenticate(method, uri string) string {
	fields := Tuple{
		"username":  s.props["user"],
		"algorithm": "MD5",
		"realm":     s.auth["realm"],
		"nonce":     s.auth["nonce"],
		"uri":       uri,
		"response": mmd5(mmd5(s.props["user"],
			s.auth["realm"],
			s.props["password"]),
			s.auth["nonce"], mmd5(method, uri)),
	}
	return "Digest " + assemble(fields, ", ", "=")
}

type server struct {
	conn     net.Conn
	props    Tuple
	auth     Tuple
	sequence int

	// doesn't need to be globally stateful?
	read, fill int
	input      reader
}

func (s *server) transact(request Tuple, message completion) {
	s.input = s.read_header(func(reply Tuple) reader {
		if reply.Gint("status") == 401 {
			a := reply.Gstring("WWW-Authenticate")
			// first term is 'Digest ' - demultiplex
			s.auth = splittymap(strings.Split(a[7:], ", "), "=")

			// strip mandatory(?) quotes
			for k, z := range s.auth {
				v := z.(string)
				s.auth[k] = v[1 : len(v)-1]
			}
			s.transact(request, message)
			// loop protection
			return s.input
		} else {
			return message(reply)
		}
		// dont have a parser if we're not expecting anything
		return nil
	})
	s.send(request)
}

func charset(x ...rune) map[rune]struct{} {
	result := make(map[rune]struct{})
	for _, i := range x {
		result[i] = struct{}{}
	}
	return result
}

func (s *server) print(length int, c completion) reader {
	size := 0
	var self reader
	self = func(b []byte) reader {
		// really max
		xfer := length - size
		avail := s.fill - s.read
		if xfer > avail {
			xfer = avail
		}
		size += xfer
		if size == length {
			return c(Tuple{})
		}
		return self
	}
	return self
}

func (s *server) read_sdp(size int, message completion) reader {
	tags := map[rune]string{
		'v': "version",
		'o': "originator",
		's': "name",
		'i': "information",
		'u': "uri",
		'z': "timezone",
		'b': "bandwidth",
		'c': "connection",
		'p': "phone",
		'e': "email",
		'm': "email",
	}
	var value = ""

	state := 0
	var tag rune
	object := make(Tuple)
	var self reader
	self = s.byrune(func(rb []byte) reader {
		r, _ := utf8.DecodeRune(rb)
		switch state {
		case 0:
			tag = r
			state++
		case 1:
			if r == '=' {
				state++
			}
		case 2:
			if r == '\r' {
				state = 3
			}
			if r == '\n' {
				state = 0
			}
			if state != 2 {
				object[tags[tag]] = value
				value = ""
			} else {
				value += string(r)
			}
		case 3:
			state = 0
		}
		return self
	})
	return s.bysize(size, self, func() reader {
		return message(object)
	})
}

func (s *server) bysize(size int, r reader, done func() reader) reader {
	total := 0
	n := r
	var self reader
	self = func(in []byte) reader {
		xfer := in
		if len(xfer) > (size - total) {
			n(in[:size-total])
			return done()(in[size-total:])
		} else {
			total += len(in)
			n = n(in)
			if total == size {
				return done()
			}
			return self
		}
	}
	return self
}

func xor(a, b bool) bool {
	return (a || b) && !(a && b)
}
func (s *server) byrune(r reader) reader {
	return func(b []byte) reader {
		size := 0
		if len(b) == 0 {
			return r
		}
		if !utf8.FullRune(b) {
			// need to keep the remainder here now
			fmt.Println("warning, reassembly failure", len(b))
			return nil
		}
		_, size = utf8.DecodeRune(b)
		next := r(b[:size])
		if xor(next == nil, (len(b[size:]) == 0)) {
			fmt.Println("termination consistency error")
		}
		if next != nil {
			return next(b[size:])
		}
		return nil
	}
}

func (s *server) read_header(message completion) reader {
	headers := make(Tuple)
	var field string
	var name string
	state := 0

	type parser struct {
		trigger map[rune]struct{}
		handler func()
		next    *parser
	}
	value := &parser{charset('\r'), func() {
		if field[0] == ' ' {
			field = field[1:]
		}
		headers[name] = field
	}, nil}
	pname := &parser{charset(':'), func() { name = field }, value}
	reason := &parser{charset('\r'), func() { headers["reason"] = field }, pname}
	status := &parser{charset(' '), func() { headers["status"] = field }, reason}
	p := &parser{charset(' '), func() { headers["protocol"] = field }, status}
	value.next = pname
	var self reader
	self = s.byrune(func(rb []byte) reader {
		r, _ := utf8.DecodeRune(rb)
		if _, ok := p.trigger[r]; ok {
			p.handler()
			p = p.next
			field = ""
		} else {
			if r != '\n' {
				field += string(r)
			}
		}

		switch r {
		case '\r':
			state++
		case '\n':
			state++
			if state == 4 {
				return message(headers)
			}
		default:
			state = 0
		}
		return self
	})
	return self
}

// transport {unicast|multicast}/profile/{udp|tcp}
func (s *server) send(request Tuple) {
	contents := make([]byte, 0, 512)
	nl := func() { contents = append(contents, []byte("\r\n")...) }
	header := func(key, value string) {
		nl()
		contents = append(contents, []byte(key+": "+value)...)
	}
	method := request.Gstring("method")
	uri := request.Gstring("uri")
	protocol := request.Gstring("protocol")
	if protocol == "" {
		protocol = s.props["protocol"].(string)
	}

	contents = append(contents, []byte(method+" "+uri+" "+protocol)...)

	z := struct{}{}

	filter := map[string]struct{}{"method": z, "uri": z, "protocol": z}

	// 'append' transport property got dropped in later version
	// source_addr, dest_addr
	transport_properties := map[string]struct{}{
		"destination": z,
		"multicast":   z, // flags
		"unicast":     z,
		"interleaved": z, // channel
		"ttl":         z,
		"layers":      z,
		"port":        z,
		"client_port": z,
		"server_port": z,
		"connection":  z, // existing, new
		"ssrc":        z,
		"mode":        z}

	transport := ""
	for k, v := range request {
		if _, ok := transport_properties[k]; ok {
			if transport != "" {
				transport += ";"
			}
			// should be encoded in v
			if k == "unicast" {
				transport += k
			} else {
				transport += k + "=" + v.(string)
			}
		}
	}

	if transport != "" {
		header("Transport", "RTP/AVP;"+transport)
	}

	for k, v := range request {
		_, is_filter := filter[k]
		_, is_transport := transport_properties[k]
		if !is_filter && !is_transport {
			header(k, v.(string))
		}
	}
	s.sequence += 1
	header("CSeq", fmt.Sprint(s.sequence))
	if s.auth != nil {
		header("Authorization", s.authenticate(method, uri))
	}
	nl()
	nl()
	fmt.Println("sending", string(contents))
	// lock
	s.conn.Write(contents)
}

func connect(props Tuple) *server {
	s := &server{props: props}
	conn, err := net.Dial("tcp", props["address"].(string)+":"+props["port"].(string))
	s.conn = conn
	if err != nil {
		fmt.Println("connecto", err)
	}

	// reader
	go func() {
		window := make([]byte, 1024, 1024)
		for {
			// clean up buffer
			bytes, err := conn.Read(window)
			if err != nil {
				fmt.Println("read error")
				// log
				return
			}
			s.fill += bytes
			s.input(window[:bytes])
		}
	}()

	return s
}

func udp_reader() string {
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		fmt.Println("connection error")
		os.Exit(-1)
	}
	me := conn.LocalAddr()
	_, meport, _ := net.SplitHostPort(me.String())
	go func() {
		var d *H264Decoder
		var reassemble []byte
		var sequence int
		var iframes, bytes int
		var dropped int
		var last time.Time
		misorder := make(map[int][]byte)

		f, e := os.Create("stream")
		if e != nil {
			fmt.Println("couldn't open storage", e)
		}
		reassemble = []byte{0, 0, 1}
		for {
			// _ is from
			buf := make([]byte, 2048) // we dont want to run this through the allocator - but reassembly
			blen, _, err := conn.ReadFrom(buf)
			if err != nil {
				fmt.Println("err", err)
				os.Exit(-1)
			}

			seq := int(buf[2])<<8 | int(buf[3])
			naltype := buf[12] & 31
			nri := buf[12] >> 5
			switch naltype {
			case 7:
				reassemble = []byte{0, 0, 0, 1}
				reassemble = append(reassemble, buf[12:blen]...)
			case 8:
				reassemble = append(reassemble, []byte{0, 0, 0, 1}...)
				reassemble = append(reassemble, buf[12:blen]...)
				if d == nil {
					d, err = NewH264Decoder(reassemble)
					i, e := d.Decode(reassemble)
					fmt.Println(i, e)
				}
				// meh

			case 28:
				fua := buf[13]

				if fua&0x80 != 0 { // start
					misorder = make(map[int][]byte)
					sequence = int(seq)
					reassemble = []byte{0, 0, 1}
					// my new nal
					reassemble = append(reassemble, fua&31|(nri<<5))
				}

				if int(seq) == sequence {
					reassemble = append(reassemble, buf[14:blen]...)
					sequence = seq + 1
				} else {
					//maybe just flatten this at the end?
					misorder[seq] = buf[14:blen]
					for {
						b, ok := misorder[sequence]
						if !ok {
							break
						}
						reassemble = append(reassemble, b...)
						delete(misorder, sequence)
						sequence++
					}
				}

				if fua&0x40 != 0 { // end
					if len(misorder) == 0 {
						// first argument is image
						_, e := d.Decode(reassemble)
						if e != nil {
							fmt.Println("decode error", e)
						}
						_, e = f.Write(reassemble) // what format do I want here?
						if e != nil {
							fmt.Println("file write error", e)
						}
						bytes += len(reassemble)
						if e != nil {
							fmt.Println("image decode error", e)
						} else {
							//							var out bytes.Buffer
							//							err = jpeg.Encode(&out, i, &jpeg.Options{Quality: 75})
							//							ioutil.WriteFile("/users/yuri/foo.jpeg", out.Bytes(), 0666)
							if fua&31 == 5 {
								fmt.Println("foo!", buf[4:8], len(reassemble), fua&31, time.Now().Sub(last), iframes)
								last = time.Now()
								iframes = 0
							} else {
								iframes++
							}

						}
					} else {
						o := ""
						for k, _ := range misorder {
							o += fmt.Sprint(k) + " "
						}
						dropped++
						//						fmt.Println("discarding partial frame reception", sequence, "ave", o)
					}

				}
			}
		}
	}()
	return meport
}

func main() {
	port := udp_reader()
	s := connect(Tuple{
		"address":  "192.168.42.70",
		"port":     "554",
		"user":     "admin",
		"password": "tmwfte",
		"protocol": "RTSP/1.0",
	})

	s.transact(Tuple{
		"method": "DESCRIBE",
		"uri":    "/"}, func(t Tuple) reader {
		return s.read_sdp(t.Gint("Content-Length"),
			func(t Tuple) reader {
				s.transact(Tuple{
					"method":      "SETUP",
					"uri":         "/trackID=1",
					"unicast":     "true",
					"server_port": "9000",
					"client_port": port}, func(t Tuple) reader {
					// why is the response in the header and not...in that other
					// stuff we got last time?
					fmt.Println("session:", t, t["Session"])
					s.transact(Tuple{"method": "PLAY",
						"Session": t["Session"]},
						func(t Tuple) reader {
							fmt.Println("play", t)
							go func() {
								for {
									time.Sleep(20 * time.Second)
									s.transact(Tuple{"method": "SET_PARAMETER",
										"keepalive": "true", //?
										"Session":   t["Session"]}, func(Tuple) reader { return nil })
								}
							}()

							return nil
						})
					return nil
				})
				return nil
			})
	})

	select {}
}
