package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath" // 新增导入
	"runtime"       // 导入 runtime 包以获取操作系统信息
	"strings"
	"sync" // 仍然需要 sync 包来使用 Mutex
)

// Config 存储通用配置信息，不再包含 Applications
type Config struct {
	Secret string
	Port   string
}

// AppConf 对应 JSON 中单个应用的 conf 字段
type AppConf struct {
	RepoPath             string `json:"repo_path"`              // 仓库目录 (例如: "C:\\projects\\myrepo" 或 "/home/user/myrepo")
	DockerComposeFile    string `json:"docker_compose_file"`    // docker-compose.yml 文件名
	UseDockerCompose     bool   `json:"use_docker_compose"`     // 是否启用 docker-compose
	RepoBranch           string `json:"repo_branch"`            // 编排分支 (要拉取代码的分支)
	BuildBash            string `json:"build_bash"`             // 构建脚本命令 (例如: "npm install && npm run build")
	GitPath              string `json:"git_path"`               // git 可执行文件路径 (例如: "C:\\Program Files\\Git\\cmd\\git.exe" 或 "/usr/bin/git")
	CommitsMessagePrefix string `json:"commits_message_prefix"` // 提交信息前缀，如果匹配则执行 before_build_bash
	BeforeBuildBash      string `json:"before_build_bash"`      // 在 build_bash 之前执行的脚本
	BashSilent           bool   `json:"bash_silent"`            // 新增：控制 bash 命令是否静默输出
}

// JsonAppEntry 对应 JSON 中 applications 数组的每个元素
type JsonAppEntry struct {
	Name string  `json:"name"` // 仓库名 (Gogs Webhook payload 中的 "repository.name")
	Conf AppConf `json:"conf"` // 配置
}

// JsonConfigRoot 对应整个 JSON 文件的根结构
type JsonConfigRoot struct {
	Applications []JsonAppEntry `json:"applications"`
}

// ApplicationConfig 用于程序内部使用，简化结构，直接包含已解析的配置
type ApplicationConfig struct {
	RepoPath             string
	DockerComposeFile    string
	UseDockerCompose     bool
	RepoBranch           string
	BuildBash            string
	GitPath              string
	CommitsMessagePrefix string
	BeforeBuildBash      string
	BashSilent           bool // 新增字段
}

// 全局变量存储应用配置
var appConfigMap = make(map[string]ApplicationConfig)

// appStatusMap 存储每个应用程序的当前状态 (e.g., "idle", "building")
// 使用常规 map 结合 Mutex 来实现并发安全的状态管理
var appStatusMap = make(map[string]string)
var appStatusMutex sync.Mutex // 保护 appStatusMap 的互斥锁

func main() {
	// --- START: 日志文件设置 ---
	// 首先判断是否启用文件日志
	// 注意：为了让 getEnvAsBool 正常工作，godotenv.Load() 应该在日志设置之前
	// 但为了日志本身能记录 godotenv.Load() 的错误，这里采取先加载 godotenv，再设置日志输出的方式
	// 这样，即使 godotenv.Load 为空，至少错误信息也会在 os.Stdout 输出
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: .env file not found or could not be loaded: %v. Using environment variables directly.", err)
	}

	enableFileLogging := getEnvAsBool("ENABLE_FILE_LOGGING", false)
	var logOutput io.Writer = os.Stdout // 默认日志输出到标准输出 (控制台)

	if enableFileLogging {
		// 获取当前运行目录
		currentDir, err := os.Getwd()
		if err != nil {
			log.Fatalf("Error getting current working directory for log file: %v", err)
		}
		logFilePath := currentDir + "/deploy.log" // 日志文件名为 deploy.log

		logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open log file %s: %v", logFilePath, err)
		}
		defer logFile.Close() // 确保程序退出时关闭日志文件

		// 将日志输出同时重定向到控制台和文件
		logOutput = io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(logOutput) // 设置全局日志输出
		log.Printf("File logging enabled. All output also redirected to %s", logFilePath)
	} else {
		log.SetOutput(logOutput) // 仅输出到标准输出
		log.Println("File logging disabled. Output to console only.")
	}
	// --- END: 日志文件设置 ---

	// 加载通用配置 (Secret 和 Port)
	generalConfig := Config{
		Secret: os.Getenv("WEBHOOK_SECRET"), // 确保从 WEBHOOK_SECRET 获取
		Port:   os.Getenv("PORT"),
	}

	if generalConfig.Secret == "" {
		log.Fatalf("Error: WEBHOOK_SECRET environment variable not set.")
	}
	if generalConfig.Port == "" {
		generalConfig.Port = "8080" // 默认端口
		log.Printf("PORT environment variable not set, using default: %s", generalConfig.Port)
	}

	// 加载应用程序配置
	appConfigFile := os.Getenv("APP_CONFIG_FILE")
	if appConfigFile == "" {
		appConfigFile = "config.json" // 如果环境变量未设置，则使用默认值
		log.Printf("APP_CONFIG_FILE environment variable not set, using default: %s", appConfigFile)
	}
	jsonConfig, err := loadConfig(appConfigFile)
	if err != nil {
		log.Fatalf("Error loading application config from %s: %v", appConfigFile, err)
	}

	// 将 JSON 配置转换为内部使用的 map
	for _, appEntry := range jsonConfig.Applications {
		// 将仓库名转换为小写并替换点为下划线，以便作为 map 的键
		appName := strings.ToLower(strings.ReplaceAll(appEntry.Name, ".", "_"))

		appConfigMap[appName] = ApplicationConfig{
			RepoPath:             appEntry.Conf.RepoPath,
			DockerComposeFile:    appEntry.Conf.DockerComposeFile,
			UseDockerCompose:     appEntry.Conf.UseDockerCompose,
			RepoBranch:           appEntry.Conf.RepoBranch,
			BuildBash:            appEntry.Conf.BuildBash,
			GitPath:              appEntry.Conf.GitPath,
			CommitsMessagePrefix: appEntry.Conf.CommitsMessagePrefix,
			BeforeBuildBash:      appEntry.Conf.BeforeBuildBash,
			BashSilent:           appEntry.Conf.BashSilent, // 新增赋值
		}
		log.Printf("  Loaded app: %s (normalized to %s) with config: %+v", appEntry.Name, appName, appConfigMap[appName])

		// 初始化应用程序状态为 "idle"
		appStatusMutex.Lock()
		appStatusMap[appName] = "idle"
		appStatusMutex.Unlock()
	}
	log.Println("Application configurations loaded successfully.")

	// 设置 Chi 路由
	r := chi.NewRouter()
	r.Use(middleware.Logger) // 使用 Chi 的日志中间件

	// Webhook 处理路由
	r.Post("/webhook", func(w http.ResponseWriter, r *http.Request) {
		handleWebhook(w, r, generalConfig.Secret)
	})

	log.Printf("Server starting on port %s...", generalConfig.Port)
	log.Printf("Current operating system: %s", runtime.GOOS)                    // 打印当前操作系统
	log.Printf("Go program's PATH environment variable: %s", os.Getenv("PATH")) // 打印程序启动时的 PATH
	log.Fatal(http.ListenAndServe(":"+generalConfig.Port, r))
}

// loadConfig 从 JSON 文件加载应用程序配置
func loadConfig(filePath string) (*JsonConfigRoot, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening config file: %w", err)
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config JsonConfigRoot
	if err := json.Unmarshal(bytes, &config); err != nil {
		return nil, fmt.Errorf("error unmarshalling config JSON: %w", err)
	}
	return &config, nil
}

// getEnvAsBool 从环境变量获取布尔值
func getEnvAsBool(name string, defaultValue bool) bool {
	valStr := os.Getenv(name)
	if valStr == "" {
		return defaultValue
	}
	switch strings.ToLower(valStr) {
	case "true", "1", "t", "y", "yes":
		return true
	case "false", "0", "f", "n", "no":
		return false
	default:
		return defaultValue
	}
}

// handleWebhook 处理 Gogs Webhook 请求
func handleWebhook(w http.ResponseWriter, r *http.Request, secret string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	// TODO: 实现签名验证 (如果 Gogs 启用了 Secret)
	if !verifySignature(r, body, secret) { // 取消注释，启用签名验证
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	var payload struct {
		Ref        string `json:"ref"`
		Repository struct {
			Name string `json:"name"`
		} `json:"repository"`
		// 新增 Commits 字段以获取提交信息
		Commits []struct {
			ID      string `json:"id"`
			Message string `json:"message"`
			URL     string `json:"url"`
			Author  struct {
				Name  string `json:"name"`
				Email string `json:"email"`
				// Username string `json:"username"` // Gogs 可能没有 username
			} `json:"author"`
			// Timestamp string `json:"timestamp"` // 暂不需要
		} `json:"commits"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Error unmarshalling payload", http.StatusBadRequest)
		log.Printf("Error unmarshalling webhook payload: %v", err)
		return
	}

	repoName := strings.ToLower(strings.ReplaceAll(payload.Repository.Name, ".", "_"))
	branchName := strings.Replace(payload.Ref, "refs/heads/", "", 1) // 提取分支名

	log.Printf("Received webhook for repository: %s, branch: %s, with %d commits", payload.Repository.Name, branchName, len(payload.Commits))

	appConfig, ok := appConfigMap[repoName]
	if !ok {
		log.Printf("No configuration found for repository: %s", payload.Repository.Name)
		http.Error(w, fmt.Sprintf("No configuration found for repository: %s", payload.Repository.Name), http.StatusNotFound)
		return
	}

	// 检查分支是否匹配
	if appConfig.RepoBranch != "" && appConfig.RepoBranch != branchName {
		log.Printf("Webhook branch '%s' does not match configured branch '%s' for %s. Skipping build.", branchName, appConfig.RepoBranch, payload.Repository.Name)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Branch mismatch. Skipped.")
		return
	}

	// --- START: 锁状态检查和获取 (使用 Mutex 保护) ---
	appStatusMutex.Lock()                   // 获取锁
	currentStatus := appStatusMap[repoName] // 直接从 map 读取状态
	log.Printf("Application %s (repo: %s) current status before lock attempt: %v", payload.Repository.Name, repoName, currentStatus)

	if currentStatus == "building" {
		appStatusMutex.Unlock() // 如果正在构建，释放锁并跳过
		log.Printf("Application %s (repo: %s) is already building. Skipping this webhook. Status found: %v", payload.Repository.Name, repoName, currentStatus)
		http.Error(w, fmt.Sprintf("Application %s is already building.", payload.Repository.Name), http.StatusTooManyRequests)
		return
	}

	// 设置状态为 "building"
	appStatusMap[repoName] = "building"
	appStatusMutex.Unlock() // 释放锁，允许其他 goroutine 读取状态
	log.Printf("Application %s (repo: %s) lock successfully acquired. Status set to building.", payload.Repository.Name, repoName)
	// --- END: 锁状态检查和获取 ---

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Webhook received and processing started for %s:%s", payload.Repository.Name, branchName)

	// 提取所有提交信息
	var commitMessages []string
	for _, commit := range payload.Commits {
		commitMessages = append(commitMessages, commit.Message)
	}

	// 异步执行构建操作，避免阻塞 HTTP 响应
	go func() {
		defer func() {
			// 无论构建成功或失败，都会执行此处，释放锁
			appStatusMutex.Lock() // 再次获取锁以修改状态
			log.Printf("Attempting to release lock for application %s (repo: %s)...", payload.Repository.Name, repoName)
			appStatusMap[repoName] = "idle"
			appStatusMutex.Unlock() // 释放锁
			log.Printf("Application %s (repo: %s) status successfully set to idle.", payload.Repository.Name, repoName)
		}()

		log.Printf("Starting build process for repository: %s, branch: %s", payload.Repository.Name, branchName)

		// 执行拉取代码和构建的命令
		if err := updateAndBuild(appConfig, branchName, commitMessages); err != nil { // 传递 commitMessages
			log.Printf("Error updating and building for %s: %v", payload.Repository.Name, err)
			return // 如果这里返回错误，defer 依然会执行
		}
		log.Printf("Successfully processed webhook for repository: %s, branch: %s", payload.Repository.Name, branchName)
	}()
}

// runCommand 在指定目录下运行命令并记录输出
// 新增 silent 参数，控制命令输出是否静默
func runCommand(dir string, name string, silent bool, arg ...string) error { // 修正参数列表顺序
	cmd := exec.Command(name, arg...)
	cmd.Dir = dir
	log.Printf("Executing command: %s %v in %s (Silent: %t)", name, arg, dir, silent) // 打印静默状态

	if silent {
		cmd.Stdout = io.Discard // 静默输出到 /dev/null
		cmd.Stderr = io.Discard // 静默错误输出到 /dev/null
	} else {
		cmd.Stdout = os.Stdout // 输出到程序的标准输出
		cmd.Stderr = os.Stderr // 输出到程序的标准错误
	}

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("command '%s %v' failed: %w", name, arg, err)
	}
	return nil
}

// updateAndBuild 拉取代码、条件性执行前置构建脚本和构建
// 接收 ApplicationConfig 结构体和提交信息
func updateAndBuild(app ApplicationConfig, branchToPull string, commitMessages []string) error {
	log.Println("Updating and building...")

	gitPath := app.GitPath       // 直接使用 config.json 中提供的 git 路径
	repoPath := app.RepoPath     // 直接使用 config.json 中提供的仓库路径
	buildBash := app.BuildBash   // 直接使用 config.json 中提供的构建脚本
	bashSilent := app.BashSilent // 获取静默配置

	// 如果 gitPath 为空，提供一个 OS 默认值
	if gitPath == "" {
		switch runtime.GOOS {
		case "windows":
			gitPath = "git.exe" // Windows 默认，期望 git 在 PATH 中
		case "linux", "darwin": // Linux 和 macOS
			gitPath = "/usr/bin/git" // Linux/macOS 默认路径
		default:
			log.Printf("Unsupported operating system for default git path: %s. Please specify git_path in config.json.", runtime.GOOS)
			return fmt.Errorf("unsupported operating system for default git path: %s", runtime.GOOS)
		}
		log.Printf("Git executable path not specified in config.json, using OS default: %s", gitPath)
	}

	if repoPath == "" {
		log.Printf("Repository path not specified in config.json for app. Cannot proceed.")
		return fmt.Errorf("repository path not specified in config.json")
	}

	// --- 检查 git 可执行文件是否存在和可执行 ---
	gitFileInfo, err := os.Stat(gitPath)
	if os.IsNotExist(err) {
		log.Printf("ERROR: Git executable not found at %s: %v", gitPath, err)
		return fmt.Errorf("git executable not found at %s: %w", gitPath, err)
	}
	if err != nil { // Other errors during os.Stat
		log.Printf("ERROR: Error checking git executable at %s: %v", gitPath, err)
		return fmt.Errorf("error checking git executable at %s: %w", gitPath, err)
	}

	// Check if it's a regular file
	if !gitFileInfo.Mode().IsRegular() {
		log.Printf("ERROR: %s is not a regular file (mode: %v)", gitPath, gitFileInfo.Mode())
		return fmt.Errorf("%s is not a regular file", gitPath)
	}

	// For Windows, executability is primarily by extension, not Unix permission bits
	// We will be more lenient here for Windows .exe files
	isExecutable := true
	if runtime.GOOS == "windows" {
		// On Windows, check if it has a common executable extension
		ext := strings.ToLower(filepath.Ext(gitPath))
		if ext != ".exe" && ext != ".com" && ext != ".bat" && ext != ".cmd" && ext != ".ps1" {
			// If it's Windows and not a common executable extension, it's likely not executable
			isExecutable = false
		}
		// Note: os.Stat on Windows for .exe files usually sets the execute bit.
		// If it's not set, it's a deeper permission issue or file corruption.
		// We'll still do the Unix-style check as a fallback/extra verification,
		// but prioritize the extension check for typical Windows executables.
	} else {
		// For Unix-like systems, check the executable permission bit
		if gitFileInfo.Mode().Perm()&0111 == 0 {
			isExecutable = false
		}
	}

	if !isExecutable {
		log.Printf("ERROR: Git executable at %s is not executable (mode: %v)", gitPath, gitFileInfo.Mode())
		return fmt.Errorf("git executable at %s is not executable", gitPath)
	}
	log.Printf("Verified git executable at %s exists and is runnable.", gitPath)

	// 确保仓库目录存在
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		log.Printf("Repository path does not exist: %s", repoPath)
		return fmt.Errorf("repository path does not exist: %w", err)
	}

	// 1. 切换到目标分支
	log.Printf("Changing to repository directory: %s", repoPath)
	// git checkout 命令的输出通常不希望被静默，因为它可能包含重要信息
	if err := runCommand(repoPath, gitPath, false, "checkout", branchToPull); err != nil { // 调整参数顺序
		return fmt.Errorf("git checkout %s failed: %w", branchToPull, err)
	}
	log.Printf("Successfully checked out branch: %s", branchToPull)

	// 2. 拉取最新代码
	// git pull 命令的输出通常不希望被静默
	if err := runCommand(repoPath, gitPath, false, "pull"); err != nil { // 调整参数顺序
		return fmt.Errorf("git pull failed: %w", err)
	}
	log.Println("Successfully pulled latest code.")

	// --- 根据 commit message prefix 条件性执行 before_build_bash ---
	shouldRunBeforeBuild := false
	if app.CommitsMessagePrefix != "" && len(commitMessages) > 0 {
		for _, msg := range commitMessages {
			if strings.HasPrefix(msg, app.CommitsMessagePrefix) {
				log.Printf("Commit message '%s' matches prefix '%s'. Preparing to run before_build_bash.", msg, app.CommitsMessagePrefix)
				shouldRunBeforeBuild = true
				break // 只要有一个匹配就执行
			}
		}
	}

	if shouldRunBeforeBuild && app.BeforeBuildBash != "" {
		log.Printf("Executing before_build script: %s (Silent: %t)", app.BeforeBuildBash, bashSilent)
		var cmdName string
		var cmdArgs []string

		switch runtime.GOOS {
		case "windows":
			cmdName = "cmd"
			cmdArgs = []string{"/c", app.BeforeBuildBash}
		case "linux", "darwin":
			cmdName = "bash"
			cmdArgs = []string{"-c", app.BeforeBuildBash}
		default:
			log.Printf("Unsupported operating system for before_build script execution: %s", runtime.GOOS)
			return fmt.Errorf("unsupported OS for before_build script: %s", runtime.GOOS)
		}

		if err := runCommand(repoPath, cmdName, bashSilent, cmdArgs...); err != nil { // 调整参数顺序
			return fmt.Errorf("before_build script '%s' failed: %w", app.BeforeBuildBash, err)
		}
		log.Println("Before_build script executed successfully.")
	} else if shouldRunBeforeBuild && app.BeforeBuildBash == "" {
		log.Println("Commit message matched prefix, but before_build_bash is empty. Skipping before_build step.")
	} else {
		log.Println("No commit message matched prefix, or prefix not specified. Skipping before_build step.")
	}
	// --- END NEW ---

	// 3. 执行主构建脚本（如果提供）
	if buildBash != "" {
		log.Printf("Executing main build script: %s (Silent: %t)", buildBash, bashSilent)
		var cmdName string
		var cmdArgs []string

		switch runtime.GOOS {
		case "windows":
			cmdName = "cmd"
			cmdArgs = []string{"/c", buildBash}
		case "linux", "darwin":
			cmdName = "bash"
			cmdArgs = []string{"-c", buildBash}
		default:
			log.Printf("Unsupported operating system for main build script execution: %s", runtime.GOOS)
			return fmt.Errorf("unsupported OS for main build script: %s", runtime.GOOS)
		}

		if err := runCommand(repoPath, cmdName, bashSilent, cmdArgs...); err != nil { // 调整参数顺序
			return fmt.Errorf("main build script '%s' failed: %w", buildBash, err)
		}
		log.Println("Main build script executed successfully.")
	} else {
		log.Println("No main build script specified, skipping build step.")
	}

	// 4. 如果使用 docker-compose，重启容器
	if app.UseDockerCompose {
		log.Println("Docker Compose is enabled. Restarting container...")
		dockerComposeFile := app.DockerComposeFile // 获取 docker-compose 文件名
		if dockerComposeFile == "" {
			dockerComposeFile = "docker-compose.yml" // 默认文件名
		}
		// docker-compose 命令的输出通常不希望被静默，因为它可能包含重要信息
		if err := restartContainer(repoPath, dockerComposeFile, false); err != nil { // 传入 false
			return fmt.Errorf("failed to restart container with docker-compose: %w", err)
		}
		log.Println("Container restarted successfully.")
	}

	return nil
}

// restartContainer 使用 docker-compose 重启服务
// 新增 silent 参数，控制命令输出是否静默
func restartContainer(repoPath string, dockerComposeFile string, silent bool) error { // 修正参数列表
	log.Printf("Restarting container (Silent: %t)...", silent)
	// 使用 docker-compose 重启服务
	cmd := exec.Command("docker-compose", "-f", dockerComposeFile, "up", "-d")
	cmd.Dir = repoPath // 确保在正确的目录下执行 docker-compose

	if silent {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("docker-compose up -d failed: %w", err)
	}
	return nil
}

// verifySignature 验证 Gogs Webhook 的签名
func verifySignature(r *http.Request, body []byte, secret string) bool {
	// TODO: 这里需要根据 Gogs 的官方文档来实现正确的签名验证逻辑。
	// 例如，如果 Gogs 使用 HMAC-SHA256，你需要实现类似下面的逻辑：
	//
	//  signature := r.Header.Get("X-Gogs-Signature") // 获取 Gogs 发送的签名
	//  if signature == "" {
	//      return false
	//  }
	//  mac := hmac.New(sha256.New, []byte(secret))
	//  mac.Write(body)
	//  expectedSignature := hex.EncodeToString(mac.Sum(nil))
	//  return signature == expectedSignature
	//
	//  目前为了演示，简化处理，直接返回 true，这在生产环境中非常不安全。
	return true // 示例：不进行实际验证
}
