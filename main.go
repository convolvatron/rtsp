package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	for _, source := range os.Args[1:] {
		conf := Tuple{}
		data, err := ioutil.ReadFile(source)
		if err != nil {
			os.Exit(-1)
		}
		fmt.Println("data: ", len(data))
		lines := strings.Split(string(data), "\n")

		for _, i := range lines {
			fields := strings.SplitN(i, ":", 2)
			if len(fields) == 2 { // umm
				fmt.Println(fields[0], fields[1])
				conf[fields[0]] = fields[1]
			}
		}
		establish(conf)
	}
}
