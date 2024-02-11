
### The file was accidentally uploaded to another gitlab account before the deadline where i wasnt able to add "juwe488c" and "rkrahn" as developer or maintainer. I mailed regarding the same. Therefore it got delayed to push the files here.

### **Task 1**

**# Getting into the crosscompiler**
```console
determine_sgx_device
docker run $MOUNT_SGXDEVICE  --network=host -it -v `pwd`:/work registry.scontain.com/sconecuratedimages/crosscompilers bash
```

**# Creating the directories **
```console
mkdir volumes/v1
```

**# Go program for printing arguments in file**
```go
cat > printargs.go << EOF
package main

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
EOF
```

**# Compile the program:**
```console
SCONE_HEAP=1G scone-gccgo printargs.go -O3 -o printargs -g
```
**# Run the program**
```console
./printargs start end
```



**# creating the namespace policy :**
export S1=printargs-1-$RANDOM
```markdown
cat > session1.yaml <<EOF
name: $S1
version: "0.3"

access_policy:
  read:
    - CREATOR
  update:
    - CREATOR
  create_sessions:
    - CREATOR
EOF
```

**# exporting scone CAS & LAS address :**
```console
export SCONE_CAS_ADDR=141.76.44.93
export SCONE_LAS_ADDR=141.76.50.190
```

**# exporting the session for S1:**
```console
export PREDECESSOR_S1=$(scone session create session1.yaml)
```

**# exporting Volume export and pr1 & pr2:**
```console
export VOLUME_EXPORT=volume-export-$RANDOM
export PR1=policy-p1-$RANDOM
 export PR2=policy-p2-$RANDOM
```

**# Creating the volume export policy**
```markdown
cat > volume-export.yaml <<EOF
name: $S1/$VOLUME_EXPORT
version: "0.3"
predecessor: $PREDECESSOR_VOLUME_EXPORT

volumes:
  - name: v1
    export:
      - session: $S1/$PR1
      - session: $S1/$PR2

images:
  - name: my_image
    volumes:
      - name: v1
        path: /volumes/v1
EOF
bash-5.1# cat volume-export.yaml 
name: printargs-1-17674/volume-export-10916
version: "0.3"
predecessor: 

volumes:
  - name: v1
    export:
      - session: printargs-1-17674/policy-p1-6558
      - session: printargs-1-17674/policy-p2-527

images:
  - name: my_image
    volumes:
      - name: v1
        path: /volumes/v1
```


**exporting the volume export policy**
```console
export PREDECESSOR_VOLUME_EXPORT=$(scone session create volume-export.yaml)
```


**# creating a secret base32 key:**
```console
sejalmanojutekar5194701assignment10
ONSWUYLMNVQW433KOV2GK23BOI2TCOJUG4YDCYLTONUWO3TNMVXHIMJQ
export OTPSECRET = ONSWUYLMNVQW433KOV2GK23BOI2TCOJUG4YDCYLTONUWO3TNMVXHIMJQ

```
**# creating a policy for task1**
```markdown
cat > p1-policy.yaml <<EOF
name: $S1/$PR1
version: "0.3"

security:
  attestation:
    tolerate: [debug-mode, hyperthreading, outdated-tcb]
    ignore_advisories: "*"
    one_time_password_shared_secret: $OTPSECRET

volumes:
  - name: v1
    import:
      session: $S1/$VOLUME_EXPORT
      volume: v1

images:
  - name: my_image
    volumes:
      - name: v1
        path: /volumes/v1

services:
   - name: printargs-go
     image_name: my_image
     mrenclaves: [$MRENCLAVE]
     command: ./printargs-go start @@1 @@2 @@3 end
     pwd: /
EOF

```
**Exporting the session for policy**
```console
export PREDECESSOR_POLICY_P1=$(scone session create p1-policy.yaml)
```

**# Executing the program**
```console
SCONE_CONFIG_ID=$SESSION/printargs-go@$OTP ./printargs-go sejalmanoj utekar 5194701
```




### **Task2**

**# Creating the go program for encrytping and decrypting the file**
```go
cat > encryptdecrypt.go << EOF
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	key1 := flag.String("key1", "", "32 byte AES key 1")
	key2 := flag.String("key2", "", "32 byte AES key 2")
	key3 := flag.String("key3", "", "32 byte AES key 3")
	flag.Parse()

	combinedKey, err := xorKeys(*key1, *key2, *key3)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Combined key: %x\n", combinedKey)

	filename := "./volumes/v1/output.txt"
	plaintext, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nContents of the file before encryption:\n\n%s\n\n", string(plaintext))

	ciphertext, err := encrypt(plaintext, combinedKey)
	if err != nil {
		log.Fatal(err)
	}

	encryptedFilename := "./out/file.txt"
	err = ioutil.WriteFile(encryptedFilename, ciphertext, 0644)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nEncrypted file written to %s\n\n", encryptedFilename)

	encryptedFile, err := os.Open(encryptedFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer encryptedFile.Close()

	decryptedFile, err := decrypt(encryptedFile, combinedKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Contents of the file after encryption:\n\n\n%s\n", string(decryptedFile))
}

func xorKeys(keys ...string) ([]byte, error) {
	var combinedKey []byte
	for _, key := range keys {
		keyBytes, err := hex.DecodeString(key)
		if err != nil {
			return nil, err
		}
		if combinedKey == nil {
			combinedKey = make([]byte, len(keyBytes))
			copy(combinedKey, keyBytes)
		} else {
			for i := range combinedKey {
				combinedKey[i] ^= keyBytes[i]
			}
		}
	}
	return combinedKey, nil
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	copy(ciphertext[:aes.BlockSize], iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func decrypt(ciphertext io.Reader, key []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(ciphertext, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var plaintext []byte
	stream := cipher.NewCFBDecrypter(block, iv)
	buf := make([]byte, 1024)
	for {
		n, err := ciphertext.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		stream.XORKeyStream(buf[:n], buf[:n])
		plaintext = append(plaintext, buf[:n]...)
	}

	return plaintext, nil
}
```


 **compiling the program **
```console
SCONE_HEAP=1G scone-gccgo encryptdecrypt.go -O3 -o encryptdecrpyt -g
```


**# Creating the policy R for KeyR & creting session for same**
```markdown
export POLICY_R=policy-r-$RANDOM
cat > policyr.yaml <<EOF
name: $S1/$POLICY_R
version: "0.3"

secrets:
  - name: keyR
    kind: binary
    size: 32
    export:
      session: $S1/$PR2
EOF
export PREDECESSOR_POLICY_R=$(scone session create policyr.yaml)
```



**# Creating the policy G for KeyG & creating session for same**
```markdown
export POLICY_G=policy-g-$RANDOM
cat > policyg.yaml <<EOF
name: $S1/$POLICY_G
version: "0.3"

secrets:
  - name: keyG
    kind: binary
    size: 32
    export:
      session: $S1/$PR2
EOF
export PREDECESSOR_POLICY_G=$(scone session create policyG.yaml)
```

**# Creating the policy B for KeyB & creating session for same**
```markdown
export POLICY_B=policy-b-$RANDOM
cat > policyb.yaml <<EOF
name: $S1/$POLICY_B
version: "0.3"

secrets:
  - name: keyB
    kind: binary
    size: 32
    export:
      session: $S1/$PR2
EOF
export PREDECESSOR_POLICY_B=$(scone session create policyG.yaml)
```

**# Creating a policy for task2 combining 3 keys**
```markdown
cat > p2-policy.yaml <<EOF
name: $S1/$PR2
version: "0.3"

security:
  attestation:
    tolerate: [debug-mode, hyperthreading, outdated-tcb]
    ignore_advisories: "*"
    one_time_password_shared_secret: $OTPSECRET

secrets:
  - name: keyR
    kind: binary
    import:
      session: $S1/$POLICY_R
      secret: keyR
  - name: keyG
    kind: binary
    import:
      session: $S1/$POLICY_G
      secret: keyG
  - name: keyB
    kind: binary
    import:
      session: $S1/$POLICY_B
      secret: keyB


volumes:
  - name: v1
    import:
      session: $S1/$VOLUME_EXPORT
      volume: v1

images:
  - name: my_image
    volumes:
      - name: v1
        path: /volumes/v1

services:
   - name: encryptdecrypt
     image_name: my_image
     command: ./encryptdecrypt -key1=\$\$SCONE::keyR:hex\$\$ -key2=\$\$SCONE::keyG:hex\$\$ -key3=\$\$SCONE::keyB:hex\$\$
     pwd: /
EOF
```

**# creating the session for policy2**
```console
export PREDECESSOR_POLICY_P2=$(scone session create p2-policy.yaml)
```

**# executing the program**
```console
SCONE_MODE=SIM SCONE_CONFIG_ID=$S1/$PR2/encryptdecrypt@OTP ./encryptdecrypt
```