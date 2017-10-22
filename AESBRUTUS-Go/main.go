package main

import (
"bytes"
"crypto/aes"
"crypto/cipher"
"encoding/base64"
"encoding/hex"
"fmt"
"regexp"
	"time"
	"runtime"
	"sync"
	"os"
	"bufio"
	"strconv"
)

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length || unpadding > 16 || unpadding <= 0{
		return nil
	}

	//fmt.Printf("%d %d\n", length, unpadding)

	/*unpaddingByte := src[length-1]
	for _, v := range src[length - unpadding: length - 1]{
		if v != unpaddingByte {
			return nil
		}
	}*/

	return src[:(length - unpadding)]
}

func decrypt(msg []byte, block cipher.Block, iv []byte) []byte {
	cfb := cipher.NewCBCDecrypter(block, iv)
	decryptMsg := make([]byte, len(msg))
	cfb.CryptBlocks(decryptMsg, msg)

	unpadMsg := Unpad(decryptMsg)

	return unpadMsg
}

func increaseByteArray(key []byte, bytesNeeded int, thread byte, threads byte){
	var startByte int
	startByte = bytesNeeded - 1
	i := startByte
	for i >= 0 {
		if i == startByte {
			key[i] += threads
			if key[i] == thread {
				i--
			} else {
				break
			}
		} else {
			key[i]++
			//overflow, go to next byte
			if key[i] == 0 {
				i--
			} else {
				break
			}
		}
	}
}

func makeKey(suffix []byte, threadStart byte, start byte) []byte{
	var bytesNeeded int = 32 - len(suffix)
	var key []byte = make([]byte, 32)

	for i := range suffix{
		key[i + bytesNeeded] = suffix[i]
	}

	key[bytesNeeded - 1] += threadStart

	key[0] += start

	return key
}

func threadDecrypt(decodedMsg []byte, iv []byte, suffix []byte, start byte, stop byte, thread byte, threads byte, log *os.File){
	var tmp []byte = make([]byte, len(decodedMsg))
	copy(tmp, decodedMsg)
	decodedMsg = tmp

	tmp = make([]byte, len(iv))
	copy(tmp, iv)
	iv = tmp

	tmp = make([]byte, len(suffix))
	copy(tmp, suffix)
	suffix = tmp

	key := makeKey(suffix, thread, start)
	var bytesNeeded int = 32 - len(suffix)

	regex, _ := regexp.Compile("\\A[\\p{L}\\s0-9.,!\"#%&'()*+_:;<=>?-{}]+\\z")

	t1nano := time.Now().UnixNano()

	var loop int = 0;
	var loops float64 = 0.0
	tmpMaxLoops := 0x1 << uint(bytesNeeded * 8)
	var startstoprange int = int(stop) - int(start)
	if(startstoprange <= 0){
		startstoprange += 256
	}

	var maxLoops float64 = float64(tmpMaxLoops) / float64(threads) * float64(startstoprange) / 256.0


	for {
		block, _ := aes.NewCipher(key)

		if thread == byte(0) {
			//fmt.Printf("PRZEDZIAL %f\n", float64(startstoprange) / 256.0)

			if loop == 1111111{
				loops += float64(loop)
				loop = 0
				percent := loops / maxLoops

				fmt.Printf("%s %.2f%s ", "Done:", 100 * percent, "% ")
				log.WriteString(fmt.Sprintf("%s %.2f%s ", "Done:", 100 * percent, "% "))

				t2nano := time.Now().UnixNano()
				elapsed := t2nano - t1nano
				estimated := int64(float64(elapsed) / percent)
				remaining := estimated - elapsed

				secElapsed := float64(elapsed % 60000000000) / 1000000000
				elapsed /= 60000000000
				minElapsed := elapsed % 60
				elapsed /= 60
				hElapsed := elapsed
				fmt.Printf("%s%d%s%d%s%2.2f%s ", "Elapsed: ", hElapsed, "h ", minElapsed, "m ", secElapsed, "s")
				log.WriteString(fmt.Sprintf("%s%d%s%d%s%2.2f%s ", "Elapsed: ", hElapsed, "h ", minElapsed, "m ", secElapsed, "s"))

				secRemaining := float64(remaining % 60000000000) / 1000000000
				remaining /= 60000000000
				minRemaining := remaining % 60
				remaining /= 60
				hRemaining := remaining
				fmt.Printf("%s%d%s%d%s%2.2f%s ", "Remaining: ", hRemaining, "h ", minRemaining, "m ", secRemaining, "s")
				log.WriteString(fmt.Sprintf("%s%d%s%d%s%2.2f%s ", "Remaining: ", hRemaining, "h ", minRemaining, "m ", secRemaining, "s"))

				secEstimated := float64(estimated % 60000000000) / 1000000000
				estimated /= 60000000000
				minEstimated := estimated % 60
				estimated /= 60
				hEstimated := estimated
				fmt.Printf("%s%d%s%d%s%2.2f%s ", "Estimated: ", hEstimated, "h ", minEstimated, "m ", secEstimated, "s")
				log.WriteString(fmt.Sprintf("%s%d%s%d%s%2.2f%s ", "Estimated: ", hEstimated, "h ", minEstimated, "m ", secEstimated, "s"))

				fmt.Printf("%s\n", hex.EncodeToString(key))
				log.WriteString(fmt.Sprintf("%s\r\n", hex.EncodeToString(key)))
			}
			loop++
		}

		decrypted := decrypt(decodedMsg, block, iv)
		if decrypted != nil {
			if regex.Match(decrypted){
				fileName := fmt.Sprintf("decrypted%d.txt", thread)
				file, _ := os.OpenFile(fileName, os.O_RDWR | os.O_CREATE, 0777)
				file.WriteString(hex.EncodeToString(key) + "\r\n" + string(decrypted))
				file.Close()

				fmt.Println(hex.EncodeToString(key))
				log.WriteString("ODSZYFROWANO!\r\n")
				log.WriteString(hex.EncodeToString(key))
				log.WriteString("\r\n")
				fmt.Println(string(decrypted))
				log.WriteString(string(decrypted))
			}
		}

		firstByteBefore := key[0]
		increaseByteArray(key, bytesNeeded, thread, threads)
		if firstByteBefore != key[0] && key[0] == stop {
			break
		}
	}
}

func main() {
	file, err := os.OpenFile("dane.txt", os.O_RDWR, 0777)

	var suffix []byte
	var iv [] byte
	var encryptMsg string
	var decodedMsg []byte

	if err != nil{
		encryptMsg = "O4WovhXdrA4zMRaTqFri8RtIYq1PvDTV/7TXG9diPi36kfCO+H8Jo5g45dKIpKk/mdYqDczHTciKVdh226CZ6BB3eT+t9nmm6AY/tAmNThkCAbyU82YBZmmKdaCnKMsE1TrG0r93gCDc69/2tDRRVw=="
		suffix, _ = hex.DecodeString("89b1349b6a9756460747ead00c4f9b8adefd9c52f27deed3fa9a36")
		iv, _ = hex.DecodeString("21e867b67ae7f20f4f4d77473d2c545c")
	} else {
		scanner := bufio.NewScanner(file)
		scanner.Scan()
		encryptMsg = scanner.Text()
		scanner.Scan()
		iv, _ = hex.DecodeString(scanner.Text())
		scanner.Scan()
		suffix, _ = hex.DecodeString(scanner.Text())
	}

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Podaj liczbe wątków:")
	scanner.Scan()
	text := scanner.Text()
	threads, err := strconv.Atoi(text)
	fmt.Println("Podaj start (włącznie) stop(wyłącznie):")
	fmt.Print("Start:")
	scanner.Scan()
	text = scanner.Text()
	start, _ := strconv.Atoi(text)
	fmt.Print("Stop:")
	scanner.Scan()
	text = scanner.Text()
	stop, _ := strconv.Atoi(text)

	runtime.GOMAXPROCS(threads)
	var wg sync.WaitGroup
	wg.Add(threads)

	decodedMsg, err = base64.StdEncoding.DecodeString(encryptMsg)
	if err != nil {
		return
	}

	var bytesNeeded int = 32 - len(suffix)

	logName := fmt.Sprintf("%d-%d log.txt", start, stop)
	log, err := os.OpenFile(logName, os.O_RDWR | os.O_CREATE, 0777)

	defer log.Close()

	fmt.Printf("Przedział %d - %d\n", start, stop)
	fmt.Printf("%s %d %s\n", "Do zdekodowania", bytesNeeded, "bajtów")

	t1 := time.Now()

	for i := 0; i < threads; i++{
		go func(decodedMsg []byte, iv []byte, suffix []byte, start byte, stop byte, thread byte, threads byte, log *os.File){
			defer wg.Done()
			fmt.Printf("%s%d\n", "Startowanie wątku ", thread)
			threadDecrypt(decodedMsg, iv, suffix, byte(start), byte(stop), byte(thread), byte(threads), log)
		}(decodedMsg, iv, suffix, byte(start), byte(stop), byte(i), byte(threads), log)
	}

	wg.Wait()

	t2 := time.Since(t1)
	fmt.Printf("%s %f %s", "Czas działania wątków: ", t2.Seconds(), "s")
}