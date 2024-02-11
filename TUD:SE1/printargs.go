ackage main

import (
        "fmt"
        "os"
)

func main() {
        if len(os.Args) < 2 {
                fmt.Println("Usage: go run program.go arg1 arg2 arg3 ...")
                os.Exit(1)
        }

        
        args := os.Args[1:]

    
        file, err := os.Create("output.txt")
        if err != nil {
                fmt.Println("Error creating file:", err)
                os.Exit(1)
        }
        defer file.Close()

        
        for i, arg := range args {
                fmt.Fprintf(file, "Argument %d: %s\n", i+1, arg)
        }

        fmt.Println("Arguments written to output.txt")
}