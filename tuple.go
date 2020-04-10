package main

import (
	"fmt"
	"strconv"
	"strings"
)

type Tuple map[string]interface{}

func (t Tuple) Gstring(key string) string {
	x := t[key]
	if x == nil {
		return ""
	}
	return x.(string)
}

func (t Tuple) Gint(key string) int {
	x := t[key]
	if x == nil {
		return 0
	}
	v, err := strconv.ParseInt(x.(string), 10, 64)
	if err != nil {
		return 0
	}
	return int(v)
}

func (t Tuple) String() string {
	var indent func(t Tuple, count int) string
	indent = func(t Tuple, count int) string {
		out := ""
		first := true
		for n, v := range t {
			if !first {
				out += strings.Repeat(" ", count)
			}
			first = false
			out += n + ": "
			if ct, ok := v.(Tuple); ok {
				out += indent(ct, count+len(n)+2)
			} else {
				out += fmt.Sprint(v) + "\n"
			}
		}
		return out
	}
	return indent(t, 0)
}
