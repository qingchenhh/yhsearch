package main

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed config.json
var embeddedConfig []byte

// ThreatEntry 表示一个威胁检测条目
type ThreatEntry struct {
	Path     string `json:"path"`     // 文件路径
	Hash     string `json:"hash"`     // SHA256哈希值（可选）
	HashType string `json:"hashType"` // 哈希类型，默认SHA256
}

// Config 配置文件结构
type Config struct {
	Threats      []ThreatEntry `json:"threats"`
	MaliciousIPs []string      `json:"maliciousIPs"`
	// 预编译的恶意IP集合，用于快速查找
	MaliciousIPSet map[string]struct{}
}

// CheckResult 检测结果
type CheckResult struct {
	Path      string
	Exists    bool
	HashMatch *bool // nil表示未提供哈希值或无法计算
	HashValue string
	Error     string
}

// ConnectionThreat 表示与恶意IP建立连接的进程详情
type ConnectionThreat struct {
	Protocol             string
	LocalAddress         string
	LocalPort            string
	RemoteAddress        string
	RemotePort           string
	State                string
	PID                  int
	ProcessName          string
	ExecutablePath       string
	CommandLine          string
	ParentPID            int
	ParentName           string
	ParentExecutablePath string
	ParentCommandLine    string
	MaliciousIP          string
}

type netstatEntry struct {
	Protocol   string
	LocalIP    string
	LocalPort  string
	RemoteIP   string
	RemotePort string
	State      string
	PID        int
}

type win32Process struct {
	ProcessID       uint32
	ParentProcessID uint32
	Name            string
	ExecutablePath  string
	CommandLine     string
}

var (
	modiphlpapi                   = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable       = modiphlpapi.NewProc("GetExtendedTcpTable")
	modntdll                      = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationProcess = modntdll.NewProc("NtQueryInformationProcess")
)

// Windows版本信息结构
type OSVERSIONINFOEX struct {
	dwOSVersionInfoSize uint32
	dwMajorVersion      uint32
	dwMinorVersion      uint32
	dwBuildNumber       uint32
	dwPlatformId        uint32
	szCSDVersion        [128]uint16
	wServicePackMajor   uint16
	wServicePackMinor   uint16
	wSuiteMask          uint16
	wProductType        byte
	wReserved           byte
}

var (
	// 是否为Windows 7或更老版本
	isWindows7OrOlder bool
)

// getWindowsVersion 获取Windows版本信息
func getWindowsVersion() (major, minor, build uint32, err error) {
	var osvi OSVERSIONINFOEX
	osvi.dwOSVersionInfoSize = uint32(unsafe.Sizeof(osvi))
	
	// 调用RtlGetVersion获取系统版本信息
	modntdll := windows.NewLazySystemDLL("ntdll.dll")
	procRtlGetVersion := modntdll.NewProc("RtlGetVersion")
	
	r1, _, err := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&osvi)))
	if r1 != 0 {
		return 0, 0, 0, fmt.Errorf("获取Windows版本信息失败: %v", err)
	}
	
	return osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber, nil
}

// initializeVersionCompatibility 初始化版本兼容性检查
func initializeVersionCompatibility() {
	major, _, _, err := getWindowsVersion()
	if err != nil {
		logWarning("无法获取Windows版本信息: %v", err)
		return
	}
	
	// Windows 7的主版本号是6
	isWindows7OrOlder = major <= 6 && major >= 1
	
	if isWindows7OrOlder {
		logInfo("检测到Windows 7或更老版本，某些功能可能有限制")
	} else {
		logDebug("检测到Windows 8或更新版本")
	}
}

// 日志级别常量
const (
	LogLevelDebug   = 0
	LogLevelInfo    = 1
	LogLevelWarning = 2
	LogLevelError   = 3
)

var (
	outputWriter io.Writer = os.Stdout
	csvWriter    *csv.Writer
	isCSVOutput  bool
	logLevel     = LogLevelInfo // 默认日志级别
	logFile      *os.File
)

func setupOutputFile(isCSV bool) (func(), error) {
	var filename string
	if isCSV {
		filename = fmt.Sprintf("result-%s.csv", time.Now().Format("20060102-150405"))
	} else {
		filename = fmt.Sprintf("result-%s.log", time.Now().Format("20060102-150405"))
	}
	
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("无法创建输出文件 %s: %v", filename, err)
	}

	isCSVOutput = isCSV
	if isCSV {
		// 对于CSV输出，我们需要创建一个csv.Writer
		csvWriter = csv.NewWriter(file)
		outputWriter = io.MultiWriter(os.Stdout, file)
	} else {
		// 对于普通输出，保持原样
		outputWriter = io.MultiWriter(os.Stdout, file)
	}
	
	return func() {
		var flushErr error
		if isCSV && csvWriter != nil {
			csvWriter.Flush()
			flushErr = csvWriter.Error()
			if flushErr != nil {
				fmt.Fprintf(os.Stderr, "警告: CSV刷新失败: %v\n", flushErr)
			}
		}
		closeErr := file.Close()
		if closeErr != nil {
			fmt.Fprintf(os.Stderr, "警告: 文件关闭失败: %v\n", closeErr)
		}
	}, nil
}

// 设置日志级别
func setLogLevel(level int) {
	logLevel = level
}

// 设置日志文件输出
func setLogFile(filePath string) error {
	// 如果已有日志文件打开，先关闭
	if logFile != nil {
		logFile.Close()
		logFile = nil
	}
	
	if filePath != "" {
		// 打开或创建日志文件
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("无法打开日志文件 %s: %v", filePath, err)
		}
		logFile = file
		// 设置输出为标准输出和日志文件的多重写入器
		outputWriter = io.MultiWriter(os.Stdout, logFile)
	} else {
		// 恢复为只输出到标准输出
		outputWriter = os.Stdout
	}
	return nil
}

// 获取当前时间戳
func getTimestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// 日志记录函数
func log(level int, prefix, format string, args ...interface{}) {
	// 根据日志级别过滤
	if level < logLevel {
		return
	}
	
	// 构造带时间戳和级别的消息
	msg := fmt.Sprintf("[%s] %s: %s\n", getTimestamp(), prefix, fmt.Sprintf(format, args...))
	fmt.Fprint(outputWriter, msg)
}

// 调试日志
func logDebug(format string, args ...interface{}) {
	log(LogLevelDebug, "DEBUG", format, args...)
}

// 信息日志
func logInfo(format string, args ...interface{}) {
	log(LogLevelInfo, "INFO", format, args...)
}

// 警告日志
func logWarning(format string, args ...interface{}) {
	log(LogLevelWarning, "WARNING", format, args...)
}

// 错误日志
func logError(format string, args ...interface{}) {
	log(LogLevelError, "ERROR", format, args...)
}

// 保留原有输出函数，但其内部使用日志系统
func outPrintf(format string, a ...interface{}) {
	fmt.Fprintf(outputWriter, format, a...)
}

func outPrintln(a ...interface{}) {
	fmt.Fprintln(outputWriter, a...)
}

func outPrint(a ...interface{}) {
	fmt.Fprint(outputWriter, a...)
}

// safeValue 返回安全的值，如果为空则返回空字符串
func safeValue(value string) string {
	return value
}

const (
	tcpTableOwnerPIDAll          = 5
	udpTableOwnerPID             = 1
	afInet                       = 2
	processBasicInformationClass = 0

	// 增强进程访问权限，在管理员模式下添加必要权限
	processQueryAccess = windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwnPID     uint32
}

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwnPID    uint32
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}

type processBasicInformation struct {
	Reserved1                    [2]uintptr
	PebBaseAddress               uintptr
	Reserved2                    [4]uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

func main() {
	// 初始化Windows版本兼容性检查
	initializeVersionCompatibility()
	
	// 在程序结束时确保关闭日志文件
	defer func() {
		if logFile != nil {
			logFile.Close()
		}
	}()
	configFlag := flag.String("config", "", "指定配置文件路径")
	listNetFlag := flag.Bool("listnet", false, "列出当前系统所有外联连接及其进程")
	flag.Parse()

	// 对于-listnet选项，使用CSV格式输出
	closeOutput, err := setupOutputFile(*listNetFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法创建结果文件: %v\n", err)
		os.Exit(1)
	}
	defer closeOutput()

	if *listNetFlag {
		// 添加性能计时
		startTime := time.Now()
		if err := printAllConnections(); err != nil {
			outPrintf("错误: 无法列出外联连接: %v\n", err)
			os.Exit(1)
		}
		outPrintf("\n外联连接信息收集完成，耗时: %v\n", time.Since(startTime))
		os.Exit(0)
	}

	var config *Config

	configPath := *configFlag
	if configPath == "" && flag.NArg() > 0 {
		configPath = flag.Arg(0)
	}

	// 如果提供了配置文件路径，使用外部配置文件；否则使用内置配置
	if configPath != "" {
		config, err = loadConfigFromFile(configPath)
		if err != nil {
			outPrintf("错误: 无法读取配置文件 %s: %v\n", configPath, err)
			os.Exit(1)
		}
	} else {
		// 使用内置配置
		config, err = loadConfigFromEmbedded()
		if err != nil {
			outPrintf("错误: 无法加载内置配置文件: %v\n", err)
			os.Exit(1)
		}
	}

	outPrintln("*****************")
	outPrintln("*银狐木马检测工具*")
	outPrintln("*****************")
	if configPath == "" {
		outPrintln("使用内置配置文件")
	} else {
		outPrintf("使用外部配置文件: %s\n", configPath)
	}
	outPrintf("加载了 %d 个恶意文件检测条目\n", len(config.Threats))
outPrintf("加载了 %d 个恶意外联IP检测条目\n\n", len(config.MaliciousIPs))

	var threatFound bool

	// 使用并发方式检查所有威胁条目
	outPrintln("开始并发检测恶意文件...")
	fileCheckStartTime := time.Now()
	results := checkThreatsConcurrently(config.Threats)
	fileCheckDuration := time.Since(fileCheckStartTime)
	outPrintf("检测完成，耗时: %v\n\n", fileCheckDuration)

	// 处理检测结果
	for _, result := range results {
		// 找到对应的原始威胁条目（注意：results的顺序可能与原始顺序不同）
		var originalThreat ThreatEntry
		for _, threat := range config.Threats {
			if threat.Path == result.Path {
				originalThreat = threat
				break
			}
		}

		if result.Exists {
			threatFound = true
			outPrintf("[威胁检测] 文件存在: %s\n", result.Path)

			// 如果存在错误（如哈希计算失败），显示错误信息
			if result.Error != "" {
				outPrintf("  ⚠️  警告: %s\n", result.Error)
			} else if result.HashMatch != nil {
				if *result.HashMatch {
					outPrintf("  ⚠️  哈希值匹配！确认是银狐木马变种\n")
					outPrintf("  文件哈希: %s\n", result.HashValue)
				} else {
					outPrintf("  ⚠️  文件存在但哈希值不匹配\n")
					outPrintf("  配置哈希: %s\n", originalThreat.Hash)
					outPrintf("  文件哈希: %s\n", result.HashValue)
				}
			} else {
				outPrintf("  ⚠️  文件存在（未配置哈希值进行验证）\n")
			}
			outPrintln()
		} else if result.Error != "" {
			outPrintf("[检测错误] %s: %s\n", result.Path, result.Error)
			outPrintln()
		}
	}

	outPrintln("开始并发检测恶意外联...")
	// 添加性能计时
	startTime := time.Now()
	networkMatches, networkErr := detectMaliciousConnections(config)
	endTime := time.Now()
	outPrintf("恶意外联检测完成，耗时: %v\n\n", endTime.Sub(startTime))
	
	if networkErr != nil {
		outPrintf("[网络检测错误] %v\n\n", networkErr)
	} else if len(networkMatches) > 0 {
		threatFound = true
		outPrintln("=========================================")
		outPrintln("恶意外联检测")
		outPrintln("=========================================")
		for _, match := range networkMatches {
			outPrintf("[外联警告] 检测到与恶意IP %s 的连接\n", match.MaliciousIP)
			outPrintf("  协议: %s  本地: %s:%s  远端: %s:%s  状态: %s\n",
				match.Protocol, match.LocalAddress, match.LocalPort, match.RemoteAddress, match.RemotePort, match.State)
			outPrintf("  进程: PID=%d  名称=%s\n", match.PID, safeValue(match.ProcessName))
			outPrintf("  路径: %s\n", safeValue(match.ExecutablePath))
			outPrintf("  启动命令: %s\n", safeValue(match.CommandLine))
			if match.ParentPID > 0 {
				outPrintf("  父进程: PID=%d  名称=%s\n", match.ParentPID, safeValue(match.ParentName))
				outPrintf("  父进程路径: %s\n", safeValue(match.ParentExecutablePath))
				outPrintf("  父进程启动命令: %s\n", safeValue(match.ParentCommandLine))
			}
			outPrintln()
		}
	}

	// 输出汇总
	outPrintln("=========================================")
outPrintln("检测汇总")
outPrintln("=========================================")

	existsCount := 0
	hashMatchCount := 0
	hashMismatchCount := 0

	for _, result := range results {
		if result.Exists {
			existsCount++
			if result.HashMatch != nil {
				if *result.HashMatch {
					hashMatchCount++
				} else {
					hashMismatchCount++
				}
			}
		}
	}

	errorCount := 0
	for _, result := range results {
		if result.Error != "" && !result.Exists {
			errorCount++
		}
	}

	networkMatchCount := len(networkMatches)
	if networkErr != nil {
		networkMatchCount = 0
	}

	outPrintf("检测恶意文件条目: %d\n", len(results))
outPrintf("发现恶意文件: %d\n", existsCount)
if hashMatchCount > 0 {
	outPrintf("⚠️  哈希值匹配（确认威胁）: %d\n", hashMatchCount)
}
if hashMismatchCount > 0 {
	outPrintf("⚠️  文件存在但哈希不匹配: %d\n", hashMismatchCount)
}
outPrintf("未发现文件: %d\n", len(results)-existsCount-errorCount)
if errorCount > 0 {
	outPrintf("检测错误: %d\n", errorCount)
}
outPrintf("检测恶意外联条目: %d\n", len(config.MaliciousIPs))
outPrintf("恶意外联: %d\n", networkMatchCount)

	if threatFound {
		outPrintln("\n⚠️  警告: 检测到可能的银狐木马痕迹！")
		os.Exit(1)
	} else {
		outPrintln("\n✓ 未检测到已知的银狐木马痕迹")
		os.Exit(0)
	}
}

// loadConfigFromFile 从外部文件加载配置文件
func loadConfigFromFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 预编译恶意IP集合，避免每次检测都重新构建
	config.compileMaliciousIPSet()

	return &config, nil
}

// loadConfigFromEmbedded 从嵌入的文件加载配置
func loadConfigFromEmbedded() (*Config, error) {
	var config Config
	err := json.Unmarshal(embeddedConfig, &config)
	if err != nil {
		return nil, fmt.Errorf("解析内置配置文件失败: %v", err)
	}

	// 预编译恶意IP集合，避免每次检测都重新构建
	config.compileMaliciousIPSet()

	return &config, nil
}

// 定义优化相关的常量和变量
const (
	// 大文件阈值，超过这个大小的文件会使用分段哈希或跳过哈希
	LargeFileThreshold = 10 * 1024 * 1024 // 10MB
	// 哈希计算缓冲区大小
	HashBufferSize = 64 * 1024 // 64KB
	// 并发处理的最大goroutine数量
	MaxConcurrentWorkers = 10
)

// PreprocessedThreat 预处理后的威胁条目，避免重复展开环境变量
type PreprocessedThreat struct {
	Original  ThreatEntry
	ExpandedPath string
}

// checkThreat 检查单个威胁条目（优化版）
func checkThreat(threat PreprocessedThreat) CheckResult {
	result := CheckResult{
		Path: threat.Original.Path,
	}

	// 检查文件是否存在
	exists, err := fileExistsWithPath(threat.ExpandedPath)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Exists = exists

	if !exists {
		return result
	}

	// 如果提供了哈希值，计算并对比
	if threat.Original.Hash != "" {
		fileHash, err := calculateFileHashOptimized(threat.ExpandedPath, threat.Original.HashType)
		if err != nil {
			// 文件存在但哈希计算失败，保留Exists=true，设置错误信息
			result.Error = fmt.Sprintf("计算哈希值失败: %v", err)
			return result
		}

		result.HashValue = fileHash

		// 对比哈希值（不区分大小写）
		configHash := strings.ToLower(strings.TrimSpace(threat.Original.Hash))
		fileHashLower := strings.ToLower(fileHash)
		match := configHash == fileHashLower
		result.HashMatch = &match
	}

	return result
}

// fileExistsWithPath 检查文件是否存在（使用已展开的路径）
func fileExistsWithPath(expandedPath string) (bool, error) {
	_, err := os.Stat(expandedPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// 目录存在缓存，避免重复检查同一目录
var directoryCache = make(map[string]bool)
var directoryCacheMutex sync.Mutex

// calculateFileHashOptimized 优化的文件哈希计算函数
func calculateFileHashOptimized(expandedPath string, hashType string) (string, error) {
	// 先检查文件信息
	fileInfo, err := os.Stat(expandedPath)
	if err != nil {
		return "", err
	}

	// 如果是目录，返回错误
	if fileInfo.IsDir() {
		return "", fmt.Errorf("路径是目录而非文件: %s", expandedPath)
	}

	file, err := os.Open(expandedPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 默认使用SHA256
	if hashType == "" {
		hashType = "sha256"
	}

	hashType = strings.ToLower(hashType)

	switch hashType {
	case "sha256":
		hasher := sha256.New()
		
		// 对于大文件使用缓冲读取
		if fileInfo.Size() > LargeFileThreshold {
			buffer := make([]byte, HashBufferSize)
			for {
				n, err := file.Read(buffer)
				if err == io.EOF {
					break
				}
				if err != nil {
					return "", err
				}
				hasher.Write(buffer[:n])
			}
		} else {
			// 小文件使用标准拷贝
			if _, err := io.Copy(hasher, file); err != nil {
				return "", err
			}
		}
		return hex.EncodeToString(hasher.Sum(nil)), nil
	default:
		return "", fmt.Errorf("不支持的哈希类型: %s", hashType)
	}
}

// 并发检查威胁条目（主优化函数）
func checkThreatsConcurrently(threats []ThreatEntry) []CheckResult {
	// 预先展开所有环境变量
	preprocessedThreats := make([]PreprocessedThreat, len(threats))
	for i, threat := range threats {
		preprocessedThreats[i] = PreprocessedThreat{
			Original:    threat,
			ExpandedPath: os.ExpandEnv(threat.Path),
		}
	}

	// 创建结果通道和任务通道
	resultsChan := make(chan CheckResult, len(preprocessedThreats))
	tasksChan := make(chan PreprocessedThreat, len(preprocessedThreats))

	// 启动工作协程池
	var wg sync.WaitGroup
	workerCount := MaxConcurrentWorkers
	if len(preprocessedThreats) < workerCount {
		workerCount = len(preprocessedThreats)
	}
	
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for threat := range tasksChan {
				resultsChan <- checkThreat(threat)
			}
		}()
	}

	// 发送任务
	for _, threat := range preprocessedThreats {
		tasksChan <- threat
	}
	close(tasksChan)

	// 等待所有工作协程完成
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// 收集结果
	results := make([]CheckResult, 0, len(preprocessedThreats))
	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

// detectMaliciousConnections 检测与恶意IP的外联情况
func detectMaliciousConnections(config *Config) ([]ConnectionThreat, error) {
	if len(config.MaliciousIPs) == 0 {
		return nil, nil
	}

	// 步骤1: 获取所有网络连接
	connections, err := getNetstatConnections()
	if err != nil {
		return nil, err
	}

	// 确保恶意IP集合已预编译
	if config.MaliciousIPSet == nil {
		config.compileMaliciousIPSet()
	}

	// 步骤2: 使用预编译的恶意IP集合（优化点：避免重复构建IP集合）

	// 步骤3: 筛选出可疑连接（连接到恶意IP的连接）
	var suspiciousConns []netstatEntry
	// 同时记录需要查询的PID，避免重复查询
	pidSet := make(map[uint32]struct{})
	
	for _, conn := range connections {
		if conn.RemoteIP == "" {
			continue
		}

		// 使用预编译的IP集合进行快速查询（优化点：避免重复的字符串处理）
		if _, ok := config.MaliciousIPSet[strings.ToLower(conn.RemoteIP)]; ok {
			suspiciousConns = append(suspiciousConns, conn)
			pidSet[uint32(conn.PID)] = struct{}{}
		}
	}

	// 步骤4: 如果没有可疑连接，直接返回
	if len(suspiciousConns) == 0 {
		return nil, nil
	}

	// 步骤5: 只为可疑连接的PID获取进程信息（优化点：避免获取所有进程信息）
	suspiciousProcessMap, err := getProcessInfoMapForSpecificPIDs(pidSet)
	if err != nil {
		return nil, err
	}

	// 步骤6: 构建结果
	var matches []ConnectionThreat
	for _, conn := range suspiciousConns {
		match := ConnectionThreat{
			Protocol:      conn.Protocol,
			LocalAddress:  conn.LocalIP,
			LocalPort:     conn.LocalPort,
			RemoteAddress: conn.RemoteIP,
			RemotePort:    conn.RemotePort,
			State:         conn.State,
			PID:           conn.PID,
			MaliciousIP:   conn.RemoteIP,
		}

		if proc, ok := suspiciousProcessMap[uint32(conn.PID)]; ok {
			match.ProcessName = proc.Name
			match.ExecutablePath = proc.ExecutablePath
			match.CommandLine = proc.CommandLine
			match.ParentPID = int(proc.ParentProcessID)
			
			// 只为有必要的父进程获取信息
			if proc.ParentProcessID > 0 {
				if parent, ok := suspiciousProcessMap[proc.ParentProcessID]; ok {
					match.ParentName = parent.Name
					match.ParentExecutablePath = parent.ExecutablePath
					match.ParentCommandLine = parent.CommandLine
				}
			}
		}

		matches = append(matches, match)
	}

	return matches, nil
}

// 常量定义
const (
	// MaxProcessWorkers 并发获取进程信息的最大工作协程数
	MaxProcessWorkers = 10
)

// processTask 表示一个获取进程信息的任务
type processTask struct {
	PID        uint32
	ProcBasic  win32Process
}

// processResult 表示进程信息获取的结果
type processResult struct {
	PID     uint32
	Process win32Process
}

// getProcessInfoMapForSpecificPIDs 只为指定的PID集合获取进程信息（并发优化版本）
// 这是一个优化函数，避免获取系统中所有进程的信息，并使用并发加速进程信息获取
func getProcessInfoMapForSpecificPIDs(pidSet map[uint32]struct{}) (map[uint32]win32Process, error) {
	// 首先获取所有进程的基本信息
	allProcessMap, err := getProcessBasicInfoMap()
	if err != nil {
		return nil, err
	}

	// 进程信息缓存，避免重复查询
	specificProcessMap := make(map[uint32]win32Process)
	parentPIDSet := make(map[uint32]struct{})

	// 步骤1: 收集需要获取详细信息的PID任务
	var taskPIDs []uint32
	for pid := range pidSet {
		if procBasic, ok := allProcessMap[pid]; ok {
			taskPIDs = append(taskPIDs, pid)
			// 记录父进程信息，稍后处理
			if procBasic.ParentProcessID > 0 {
				parentPIDSet[procBasic.ParentProcessID] = struct{}{}
			}
		}
	}

	// 步骤2: 并发获取进程详细信息
	processResults, err := getProcessDetailsConcurrently(taskPIDs, allProcessMap)
	if err != nil {
		return nil, err
	}

	// 步骤3: 合并结果
	for _, result := range processResults {
		specificProcessMap[result.PID] = result.Process
	}

	// 步骤4: 为父进程获取详细信息（也使用并发）
	var parentTaskPIDs []uint32
	for parentPID := range parentPIDSet {
		if _, exists := specificProcessMap[parentPID]; !exists {
			if _, ok := allProcessMap[parentPID]; ok {
				parentTaskPIDs = append(parentTaskPIDs, parentPID)
			}
		}
	}

	// 并发获取父进程详细信息
	if len(parentTaskPIDs) > 0 {
		parentResults, err := getProcessDetailsConcurrently(parentTaskPIDs, allProcessMap)
		if err != nil {
			return nil, err
		}

		// 合并父进程结果
		for _, result := range parentResults {
			specificProcessMap[result.PID] = result.Process
		}
	}

	return specificProcessMap, nil
}

// getProcessDetailsConcurrently 并发获取多个进程的详细信息
func getProcessDetailsConcurrently(pids []uint32, basicInfoMap map[uint32]win32Process) ([]processResult, error) {
	// 如果没有任务，直接返回
	if len(pids) == 0 {
		return nil, nil
	}

	// 创建任务队列
	taskQueue := make(chan processTask, len(pids))
	// 创建结果队列
	resultQueue := make(chan processResult, len(pids))
	// 用于同步所有工作协程
	var wg sync.WaitGroup
	// 用于保护错误信息
	var mutex sync.Mutex
	var lastError error

	// 确定工作协程数量（不超过最大工作协程数和任务数量）
	workerCount := MaxProcessWorkers
	if len(pids) < workerCount {
		workerCount = len(pids)
	}

	// 启动工作协程
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			// 创建进程信息提供者管理器
			providerManager := NewProcessInfoProviderManager()
			
			// 处理任务队列中的每个任务
			for task := range taskQueue {
				// 获取进程详细信息
				exePath, cmdLine, err := providerManager.GetProcessDetails(task.PID)
				if err != nil {
					// 记录最后一个错误，但继续处理其他任务
					mutex.Lock()
					lastError = err
					mutex.Unlock()
					
					// 仍然返回基本信息
					resultQueue <- processResult{
						PID: task.PID,
						Process: win32Process{
							ProcessID:       task.PID,
							ParentProcessID: task.ProcBasic.ParentProcessID,
							Name:            task.ProcBasic.Name,
							ExecutablePath:  "",
							CommandLine:     "",
						},
					}
					continue
				}

				// 构建完整的进程信息
				process := win32Process{
					ProcessID:       task.PID,
					ParentProcessID: task.ProcBasic.ParentProcessID,
					Name:            task.ProcBasic.Name,
					ExecutablePath:  exePath,
					CommandLine:     cmdLine,
				}

				// 发送结果
				resultQueue <- processResult{
					PID:     task.PID,
					Process: process,
				}
			}
		}()
	}

	// 填充任务队列
	for _, pid := range pids {
		if procBasic, ok := basicInfoMap[pid]; ok {
			taskQueue <- processTask{
				PID:       pid,
				ProcBasic: procBasic,
			}
		}
	}
	close(taskQueue) // 关闭任务队列，通知工作协程没有更多任务

	// 等待所有工作协程完成
	go func() {
		wg.Wait()
		close(resultQueue) // 所有工作完成后关闭结果队列
	}()

	// 收集结果
	var results []processResult
	for result := range resultQueue {
		results = append(results, result)
	}

	// 返回最后一个错误（如果有），但仍然返回已收集的结果
	if lastError != nil {
		// 仅记录错误，不中断执行，因为我们可能已经获取了部分进程信息
		logInfo("获取部分进程信息时出错: %v", lastError)
	}

	return results, nil
}

// compileMaliciousIPSet 预编译恶意IP集合，提高匹配效率
func (c *Config) compileMaliciousIPSet() {
	// 初始化map
	c.MaliciousIPSet = make(map[string]struct{})
	
	// 一次性规范化并存储所有IP地址
	for _, ip := range c.MaliciousIPs {
		trimmed := strings.ToLower(strings.TrimSpace(ip))
		if trimmed != "" {
			c.MaliciousIPSet[trimmed] = struct{}{}
		}
	}
}

// getProcessBasicInfoMap 获取所有进程的基本信息（PID、父PID、进程名）
// 这个函数只获取进程的基本信息，不获取详细路径和命令行
func getProcessBasicInfoMap() (map[uint32]win32Process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("获取进程快照失败: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	result := make(map[uint32]win32Process)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		pid := entry.ProcessID
		parent := entry.ParentProcessID
		name := windows.UTF16ToString(entry.ExeFile[:])

		// 只存储基本信息，不获取详细路径和命令行
		result[pid] = win32Process{
			ProcessID:       pid,
			ParentProcessID: parent,
			Name:            name,
			ExecutablePath:  "", // 将在需要时填充
			CommandLine:     "", // 将在需要时填充
		}

		err = windows.Process32Next(snapshot, &entry)
	}

	if err != syscall.ERROR_NO_MORE_FILES {
		return nil, fmt.Errorf("遍历进程列表失败: %v", err)
	}

	return result, nil
}

func printAllConnections() error {
	connections, err := getNetstatConnections()
	if err != nil {
		return err
	}

	// 提取所有连接相关的PID
	pids := make(map[uint32]struct{})
	for _, conn := range connections {
		pids[uint32(conn.PID)] = struct{}{}
	}

	// 只获取与连接相关的进程信息
	processMap, err := getProcessInfoMapForSpecificPIDs(pids)
	if err != nil {
		return err
	}

	if len(connections) == 0 {
		if !isCSVOutput {
			outPrintln("未发现活动的外联连接")
		}
		return nil
	}

	// 根据输出类型选择不同的写入方式
	if isCSVOutput && csvWriter != nil {
		// CSV模式：写入表头
		headers := []string{"序号", "协议", "本地地址", "本地端口", "远程地址", "远程端口", "连接状态", "进程ID", "进程名称", "进程路径", "启动命令行", "父进程ID", "父进程名称", "父进程路径", "父进程启动命令行", "DLL数量", "DLL列表"}
		if err := csvWriter.Write(headers); err != nil {
			return fmt.Errorf("写入CSV表头失败: %v", err)
		}
		
		// 写入数据行
		for idx, conn := range connections {
			// 准备基本数据
			row := []string{
				strconv.Itoa(idx + 1),
				conn.Protocol,
				conn.LocalIP,
				conn.LocalPort,
				conn.RemoteIP,
				conn.RemotePort,
				conn.State,
				strconv.Itoa(conn.PID),
				"", "", "", "", "", "", "", "", "",
			}
			
			// 添加进程信息
			if proc, ok := processMap[uint32(conn.PID)]; ok {
				row[8] = safeValue(proc.Name)    // 进程名称
				row[9] = safeValue(proc.ExecutablePath) // 进程路径
				row[10] = safeValue(proc.CommandLine)   // 启动命令行
				
				// 添加父进程信息
				if parent, ok := processMap[proc.ParentProcessID]; ok {
					row[11] = strconv.Itoa(int(parent.ProcessID)) // 父进程ID
					row[12] = safeValue(parent.Name) // 父进程名称
					row[13] = safeValue(parent.ExecutablePath) // 父进程路径
					row[14] = safeValue(parent.CommandLine) // 父进程启动命令行
				} else if proc.ParentProcessID != 0 {
					row[11] = strconv.Itoa(int(proc.ParentProcessID)) // 父进程ID
				}

				// 暂时不获取DLL信息以提升性能
				row[15] = "-" // DLL数量
				row[16] = "性能优化中暂不获取DLL信息"
			}
			
			// 写入行
			if err := csvWriter.Write(row); err != nil {
				return fmt.Errorf("写入CSV行失败: %v", err)
			}
		}
		
		// 刷新CSV写入器
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			return fmt.Errorf("刷新CSV写入器失败: %v", err)
		}
	} else {
		// 普通文本模式
		for idx, conn := range connections {
			outPrintln("--------------------------------")
			outPrintf("序号:%d\n", idx+1)
			outPrintf("本地地址:%s:%s\n", conn.LocalIP, conn.LocalPort)
			outPrintf("远程地址:%s:%s\n", conn.RemoteIP, conn.RemotePort)
			outPrintf("连接状态:%s\n", conn.State)
			outPrintf("进程ID:%d\n", conn.PID)

			if proc, ok := processMap[uint32(conn.PID)]; ok {
				outPrintf("进程名称:%s\n", safeValue(proc.Name))
				outPrintf("进程路径:%s\n", safeValue(proc.ExecutablePath))
				outPrintf("启动命令行:%s\n", safeValue(proc.CommandLine))

				if parent, ok := processMap[proc.ParentProcessID]; ok {
					outPrintf("父进程ID:%d\n", parent.ProcessID)
					outPrintf("父进程名称:%s\n", safeValue(parent.Name))
					outPrintf("父进程路径:%s\n", safeValue(parent.ExecutablePath))
					outPrintf("父进程启动命令行:%s\n", safeValue(parent.CommandLine))
				} else if proc.ParentProcessID != 0 {
					outPrintf("父进程ID:%d\n", proc.ParentProcessID)
					outPrintln("父进程信息: 未获取到")
				}

				// 暂时不获取DLL信息以提升性能
				outPrintln("加载的DLL: 性能优化中暂不获取DLL信息")
			} else {
				outPrintln("进程信息: 未获取到")
			}
		}
		outPrintln("--------------------------------")
	}
	return nil
}

func getNetstatConnections() ([]netstatEntry, error) {
	tcpEntries, err := getExtendedTCPEntries()
	if err != nil {
		return nil, err
	}

	return tcpEntries, nil
}

func getExtendedTCPEntries() ([]netstatEntry, error) {
	rows, err := fetchTCPTable()
	if err != nil {
		return nil, err
	}

	entries := make([]netstatEntry, 0, len(rows))
	for _, row := range rows {
		localIP := formatIPv4(row.LocalAddr)
		remoteIP := formatIPv4(row.RemoteAddr)
		if remoteIP == "0.0.0.0" {
			continue
		}

		entry := netstatEntry{
			Protocol:   "TCP",
			LocalIP:    localIP,
			LocalPort:  strconv.Itoa(int(ntohs(row.LocalPort))),
			RemoteIP:   remoteIP,
			RemotePort: strconv.Itoa(int(ntohs(row.RemotePort))),
			State:      tcpStateToString(row.State),
			PID:        int(row.OwnPID),
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func fetchTCPTable() ([]mibTCPRowOwnerPID, error) {
	if err := procGetExtendedTcpTable.Find(); err != nil {
		return nil, err
	}

	var size uint32
	ret, _, err := procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1,
		uintptr(afInet),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && ret != 0 {
		return nil, err
	}

	buffer := make([]byte, size)
	ret, _, err = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		uintptr(afInet),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if ret != 0 {
		return nil, err
	}

	count := *(*uint32)(unsafe.Pointer(&buffer[0]))
	rows := make([]mibTCPRowOwnerPID, 0, count)
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	base := uintptr(unsafe.Pointer(&buffer[0])) + unsafe.Sizeof(count)

	for i := uint32(0); i < count; i++ {
		ptr := unsafe.Pointer(base + uintptr(i)*rowSize)
		rows = append(rows, *(*mibTCPRowOwnerPID)(ptr))
	}

	return rows, nil
}

func formatIPv4(addr uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, addr)
	return net.IP(b).String()
}

func ntohs(port uint32) uint16 {
	return uint16((port>>8)&0xff | (port<<8)&0xff00)
}

func tcpStateToString(state uint32) string {
	switch state {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN-SENT"
	case 4:
		return "SYN-RECEIVED"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN-WAIT-1"
	case 7:
		return "FIN-WAIT-2"
	case 8:
		return "CLOSE-WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST-ACK"
	case 11:
		return "TIME-WAIT"
	case 12:
		return "DELETE-TCB"
	default:
		return "UNKNOWN"
	}
}

func getProcessInfoMap() (map[uint32]win32Process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("获取进程快照失败: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	// 创建进程信息提供者管理器
	providerManager := NewProcessInfoProviderManager()

	result := make(map[uint32]win32Process)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		pid := entry.ProcessID
		parent := entry.ParentProcessID
		name := windows.UTF16ToString(entry.ExeFile[:])

		// 使用提供者管理器获取进程详情
		exePath, cmdLine, _ := providerManager.GetProcessDetails(pid)
		result[pid] = win32Process{
			ProcessID:       pid,
			ParentProcessID: parent,
			Name:            name,
			ExecutablePath:  exePath,
			CommandLine:     cmdLine,
		}

		err = windows.Process32Next(snapshot, &entry)
	}

	if err != syscall.ERROR_NO_MORE_FILES {
		return nil, fmt.Errorf("遍历进程列表失败: %v", err)
	}

	return result, nil
}

// ProcessInfoProvider 定义进程信息获取的接口
type ProcessInfoProvider interface {
	// GetProcessDetails 获取进程的详细信息
	GetProcessDetails(pid uint32) (string, string, error)
	// GetName 返回提供者名称
	GetName() string
	// IsAvailable 检查提供者是否可用
	IsAvailable() bool
}

// NativeProcessInfoProvider 使用Windows原生API获取进程信息
type NativeProcessInfoProvider struct{}

// GetProcessDetails 使用Windows API获取进程信息
func (p *NativeProcessInfoProvider) GetProcessDetails(pid uint32) (string, string, error) {
	// 定义不同级别的访问权限，从最低到最高
	accessLevels := []uint32{
		// 最低权限级别：仅查询有限信息
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		// 中级权限：增加VM读取权限
		windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_VM_READ,
		// 高级权限：完整的查询和内存操作权限
		windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_VM_READ | 
			windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_OPERATION,
	}

	var handle windows.Handle
	var err error

	// 渐进式尝试不同级别的权限
	for _, access := range accessLevels {
		handle, err = windows.OpenProcess(access, false, pid)
		if err == nil {
			break
		}
	}

	// 如果无法打开进程，返回错误
	if err != nil {
		return "", "", fmt.Errorf("无法打开进程 (PID: %d): %v", pid, err)
	}

	// 确保句柄正确关闭
	defer func() {
		if handle != 0 {
			windows.CloseHandle(handle)
		}
	}()

	// 获取进程路径
	path, err := queryProcessImagePath(handle)
	if err != nil {
		return "", "", fmt.Errorf("获取进程路径失败: %v", err)
	}

	// 获取进程命令行
	cmdLine, cmdErr := queryProcessCommandLine(handle)
	if cmdErr != nil {
		return path, "", fmt.Errorf("获取命令行失败: %v", cmdErr)
	}

	return path, cmdLine, nil
}

// GetName 返回提供者名称
func (p *NativeProcessInfoProvider) GetName() string {
	return "Native API"
}

// IsAvailable 检查提供者是否可用
func (p *NativeProcessInfoProvider) IsAvailable() bool {
	// Windows原生API几乎总是可用的
	return true
}

// WMICProcessInfoProvider 使用WMIC命令获取进程信息
type WMICProcessInfoProvider struct{}

// GetProcessDetails 使用WMIC获取进程信息
func (p *WMICProcessInfoProvider) GetProcessDetails(pid uint32) (string, string, error) {
	// 获取命令行
	cmdLine, err := getCommandLineUsingWMICWithError(pid)
	if err != nil {
		return "", "", fmt.Errorf("WMIC方法获取命令行失败: %v", err)
	}

	// 尝试获取进程路径
	path, pathErr := getProcessPathUsingWMIC(pid)
	if pathErr != nil {
		// 路径获取失败但仍返回命令行
		return "", cmdLine, nil
	}

	return path, cmdLine, nil
}

// GetName 返回提供者名称
func (p *WMICProcessInfoProvider) GetName() string {
	return "WMIC"
}

// IsAvailable 检查WMIC是否可用
func (p *WMICProcessInfoProvider) IsAvailable() bool {
	// 简单检查WMIC命令是否可用
	_, err := exec.Command("cmd.exe", "/c", "wmic /?").CombinedOutput()
	return err == nil
}

// ProcessInfoProviderManager 进程信息提供者管理器
type ProcessInfoProviderManager struct {
	providers []ProcessInfoProvider
}

// NewProcessInfoProviderManager 创建新的提供者管理器
func NewProcessInfoProviderManager() *ProcessInfoProviderManager {
	manager := &ProcessInfoProviderManager{
		providers: []ProcessInfoProvider{
			&NativeProcessInfoProvider{},
			&WMICProcessInfoProvider{},
		},
	}
	
	// 过滤掉不可用的提供者
	availableProviders := []ProcessInfoProvider{}
	for _, provider := range manager.providers {
		if provider.IsAvailable() {
			availableProviders = append(availableProviders, provider)
		}
	}
	manager.providers = availableProviders
	
	return manager
}

// GetProcessDetails 尝试使用所有可用的提供者获取进程信息
func (m *ProcessInfoProviderManager) GetProcessDetails(pid uint32) (string, string, error) {
	if len(m.providers) == 0 {
		return "", "", fmt.Errorf("没有可用的进程信息提供者")
	}

	var lastErr error
	
	// 尝试所有提供者
	for _, provider := range m.providers {
		path, cmdLine, err := provider.GetProcessDetails(pid)
		if err == nil {
			return path, cmdLine, nil
		}
		lastErr = fmt.Errorf("提供者 %s 失败: %v", provider.GetName(), err)
	}

	// 如果所有提供者都失败，返回最后一个错误
	return "", "", lastErr
}

func getProcessModules(pid uint32) ([]string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		return nil, fmt.Errorf("创建模块快照失败 (PID: %d): %v", pid, err)
	}
	defer windows.CloseHandle(snapshot)

	// 初始化MODULEENTRY32结构体
	var mod windows.ModuleEntry32
	mod.Size = uint32(unsafe.Sizeof(mod))

	// 获取第一个模块
	err = windows.Module32First(snapshot, &mod)
	if err != nil {
		// 特别处理ERROR_NO_MORE_FILES错误，表示没有找到模块
		if err == windows.ERROR_NO_MORE_FILES || err == syscall.ERROR_NO_MORE_FILES {
			return []string{}, nil
		}
		return nil, fmt.Errorf("获取第一个模块信息失败 (PID: %d): %v", pid, err)
	}

	var modules []string

	// 循环获取所有模块
	for {
		modulePath := windows.UTF16ToString(mod.ExePath[:])
		modules = append(modules, modulePath)

		// 获取下一个模块
		err := windows.Module32Next(snapshot, &mod)
		if err != nil {
			// ERROR_NO_MORE_FILES表示已经遍历完所有模块
			if err == windows.ERROR_NO_MORE_FILES || err == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return nil, fmt.Errorf("获取下一个模块信息失败 (PID: %d): %v", pid, err)
		}
	}

	return modules, nil
}

// queryProcessImagePath 获取进程的完整路径，正确返回错误信息
func queryProcessImagePath(handle windows.Handle) (string, error) {
	size := uint32(260)
	for i := 0; i < 3; i++ {
		buffer := make([]uint16, size)
		copied := size
		err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &copied)
		if err == nil {
			return windows.UTF16ToString(buffer[:copied]), nil
		} else if err == windows.ERROR_INSUFFICIENT_BUFFER {
			size *= 2
			continue
		} else {
			return "", fmt.Errorf("QueryFullProcessImageName失败: %v", err)
		}
	}
	return "", fmt.Errorf("获取进程路径失败：尝试3次后仍无法成功")
}

// getCommandLineUsingNtQuery 使用NT API读取进程内存获取命令行信息
// 实现完整的边界检查和内存安全防护
func getCommandLineUsingNtQuery(handle windows.Handle) (string, error) {
	// 定义必要的结构体
	type UnicodeString struct {
		Length        uint16
		MaximumLength uint16
		Buffer        uintptr
	}

	type ProcessParameters struct {
		Reserved1           [16]byte
		ImagePathName       UnicodeString
		CommandLine         UnicodeString
	}

	type PEB struct {
		Reserved1          [2]byte
		BeingDebugged      byte
		Reserved2          [1]byte
		Reserved3          [2]uintptr
		Ldr                uintptr
		ProcessParameters  uintptr
	}

	// 1. 获取PEB地址
	var pbi processBasicInformation
	var retLen uint32
	status, _, err := procNtQueryInformationProcess.Call(
		uintptr(handle),
		processBasicInformationClass,
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)

	if status != 0 {
		return "", fmt.Errorf("NtQueryInformationProcess failed with status 0x%x: %v", status, err)
	}

	// 2. 验证PEB地址有效性
	if pbi.PebBaseAddress == 0 {
		return "", fmt.Errorf("invalid PEB address")
	}

	// 3. 读取PEB结构
	var peb PEB
	numRead := uint32(0)
	err = windows.ReadProcessMemory(
		handle,
		pbi.PebBaseAddress,
		(*byte)(unsafe.Pointer(&peb)),
		uintptr(unsafe.Sizeof(peb)),
		(*uintptr)(unsafe.Pointer(&numRead)),
	)

	if err != nil {
		return "", fmt.Errorf("failed to read PEB: %v", err)
	}

	if uintptr(numRead) != unsafe.Sizeof(peb) {
		return "", fmt.Errorf("incomplete PEB read")
	}

	// 4. 验证ProcessParameters地址有效性
	if peb.ProcessParameters == 0 {
		return "", fmt.Errorf("invalid ProcessParameters address")
	}

	// 5. 读取ProcessParameters结构
	var params ProcessParameters
	err = windows.ReadProcessMemory(
		handle,
		peb.ProcessParameters,
		(*byte)(unsafe.Pointer(&params)),
		uintptr(unsafe.Sizeof(params)),
		(*uintptr)(unsafe.Pointer(&numRead)),
	)

	if err != nil {
		return "", fmt.Errorf("failed to read ProcessParameters: %v", err)
	}

	if uintptr(numRead) != unsafe.Sizeof(params) {
		return "", fmt.Errorf("incomplete ProcessParameters read")
	}

	// 6. 验证命令行信息有效性
	if params.CommandLine.Length == 0 || params.CommandLine.Buffer == 0 {
		return "", fmt.Errorf("command line not available")
	}

	// 7. 安全检查：限制最大读取长度，防止恶意超长命令行
	maxReadLength := uint32(65536) // 64KB 最大限制
	if uint32(params.CommandLine.Length) > maxReadLength {
		return "", fmt.Errorf("command line too long")
	}

	// 8. 读取命令行字符串
	buffer := make([]uint16, params.CommandLine.MaximumLength/2)
	err = windows.ReadProcessMemory(
		handle,
		params.CommandLine.Buffer,
		(*byte)(unsafe.Pointer(&buffer[0])),
		uintptr(params.CommandLine.Length),
		(*uintptr)(unsafe.Pointer(&numRead)),
	)

	if err != nil {
		return "", fmt.Errorf("failed to read command line string: %v", err)
	}

	if numRead == 0 {
		return "", fmt.Errorf("empty command line read")
	}

	// 9. 转换为Go字符串
	cmdLine := windows.UTF16ToString(buffer[:params.CommandLine.Length/2])

	return cmdLine, nil
}





// getCommandLineUsingWMIC 使用WMIC命令获取进程命令行，支持错误处理
func getCommandLineUsingWMIC(pid uint32) (string, error) {
	cmd := fmt.Sprintf("wmic process where ProcessId=%d get CommandLine /format:list", pid)
	// 设置10秒超时
	timeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// 使用CommandContext创建带超时的命令
	command := exec.CommandContext(ctx, "cmd.exe", "/c", cmd)
	
	output, err := command.CombinedOutput() // 使用CombinedOutput获取标准输出和错误输出
	if err != nil {
		// 检查是否超时
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("获取进程PID %d 命令行超时（%v）", pid, timeout)
		}
		// 包含命令的错误输出到错误信息中
		errorOutput := strings.TrimSpace(string(output))
		if errorOutput != "" {
			return "", fmt.Errorf("WMIC命令执行失败 (PID: %d): %v, 错误输出: %s", pid, err, errorOutput)
		}
		return "", fmt.Errorf("WMIC命令执行失败 (PID: %d): %v", pid, err)
	}
	
	outputStr := strings.TrimSpace(string(output))
	// 检查输出是否有效
	if outputStr == "" {
		return "", fmt.Errorf("WMIC命令返回空结果 (PID: %d)", pid)
	}
	
	// 检查是否包含No Instance(s) Available错误
	if strings.Contains(strings.ToLower(outputStr), "no instance") {
		return "", fmt.Errorf("找不到进程实例 (PID: %d)", pid)
	}
	
	// 尝试提取CommandLine值
	if strings.Contains(outputStr, "CommandLine=") {
		parts := strings.SplitN(outputStr, "=", 2)
		if len(parts) == 2 {
			cmdLine := strings.TrimSpace(parts[1])
			// 确保返回的命令行不为空
			if cmdLine != "" {
				return cmdLine, nil
			}
			return "", fmt.Errorf("提取到空命令行 (PID: %d)", pid)
		}
	}
	// 提供更详细的输出格式信息，帮助调试
	return "", fmt.Errorf("WMIC命令输出格式无效或未找到命令行信息 (PID: %d), 输出: %q", pid, outputStr)
}








// getProcessIdFromHandle 通过进程句柄获取进程ID
func getProcessIdFromHandle(handle windows.Handle) (uint32, error) {
	// Windows 7及更早版本可能需要不同的处理方式
	if isWindows7OrOlder {
		logDebug("在Windows 7或更老版本上使用备用方法获取进程ID")
		// 使用GetProcessId函数，但添加额外的错误处理
		id, err := windows.GetProcessId(handle)
		if err != nil {
			// 如果GetProcessId失败，可以尝试使用NtQueryInformationProcess作为备选
			logWarning("GetProcessId失败: %v，尝试备选方法", err)
			// 对于Windows 7，我们仍然优先使用GetProcessId，但提供更好的错误处理
			return 0, fmt.Errorf("无法从句柄获取进程ID: %v", err)
		}
		return id, nil
	} else {
		// Windows 8及更新版本，使用标准方法
		id, err := windows.GetProcessId(handle)
		return id, err
	}
}





// getCommandLineUsingWMICWithError 使用WMIC命令获取进程命令行（带错误返回）
func getCommandLineUsingWMICWithError(pid uint32) (string, error) {
	cmd := fmt.Sprintf("wmic process where ProcessId=%d get CommandLine /format:list", pid)
	output, err := exec.Command("cmd.exe", "/c", cmd).Output()
	if err != nil {
		return "", err
	}
	
	outputStr := string(output)
	if strings.Contains(outputStr, "CommandLine=") {
		parts := strings.SplitN(outputStr, "=", 2)
		if len(parts) == 2 {
			cmdLine := strings.TrimSpace(parts[1])
			return cmdLine, nil
		}
	}
	return "", fmt.Errorf("无法解析WMIC输出")
}

// queryProcessCommandLine 从进程句柄获取命令行
func queryProcessCommandLine(handle windows.Handle) (string, error) {
	// 获取进程ID
	pid, err := windows.GetProcessId(handle)
	if err != nil {
		return "", fmt.Errorf("获取进程ID失败: %v", err)
	}
	
	logDebug("查询进程命令行 (PID: %d)", pid)
	
	// 为Windows 7及更早版本提供特殊处理
	if isWindows7OrOlder {
		logDebug("在Windows 7或更老版本上获取进程命令行")
		// 在Windows 7上，使用WMIC方法
		return getCommandLineUsingWMICWithError(pid)
	}
	
	// Windows 8及更新版本，使用标准方法
	return getCommandLineUsingWMICWithError(pid)
}

// getProcessPathUsingWMIC 使用WMIC命令获取进程路径
func getProcessPathUsingWMIC(pid uint32) (string, error) {
	cmd := fmt.Sprintf("wmic process where ProcessId=%d get ExecutablePath /format:list", pid)
	output, err := exec.Command("cmd.exe", "/c", cmd).Output()
	if err != nil {
		return "", err
	}
	
	outputStr := string(output)
	if strings.Contains(outputStr, "ExecutablePath=") {
		parts := strings.SplitN(outputStr, "=", 2)
		if len(parts) == 2 {
			path := strings.TrimSpace(parts[1])
			return path, nil
		}
	}
	return "", fmt.Errorf("无法解析WMIC输出")
}

