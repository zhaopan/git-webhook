package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv" // 用于加载 .env 文件
)

// Config 存储通用配置信息，不再包含 Applications
type Config struct {
	Secret string
	Port   string
}

// AppConf 对应 JSON 中单个应用的 conf 字段
type AppConf struct {
	RepoPath          string `json:"repo_path"`
	DockerComposeFile string `json:"docker_compose_file"`
	UseDockerCompose  bool   `json:"use_docker_compose"`
	RepoBranch        string `json:"repo_branch"` 
	BuildBash         string `json:"build_bash"` 
}

// JsonAppEntry 对应 JSON 中 applications 数组的每个元素
type JsonAppEntry struct {
	Name string  `json:"name"`
	Conf AppConf `json:"conf"`
}

// JsonConfigRoot 对应整个 JSON 文件的根结构
type JsonConfigRoot struct {
	Applications []JsonAppEntry `json:"applications"`
}

// ApplicationConfig 与之前的 ApplicationConfig 保持一致，用于程序内部使用
type ApplicationConfig struct {
	RepoPath          string
	DockerComposeFile string
	UseDockerCompose  bool
	RepoBranch        string // 新增字段
	BuildBash         string // 新增字段
}

var config struct { // 使用匿名结构体来组合通用配置和应用程序配置
	Secret      string
	Port        string
	Applications map[string]ApplicationConfig // 使用 map 存储应用程序配置，key 为应用程序名称
}

// appStatusMap 存储应用程序的构建状态
var appStatusMap sync.Map // 使用 sync.Map 实现并发安全的 map
//  key: 应用程序名称 (string), value: 应用程序状态 (string)
//  可能的应用程序状态: "idle", "building"

func main() {
	// 加载 .env 文件 (用于 Secret 和 Port 等通用配置)
	if err := godotenv.Load(); err != nil {
		log.Println("Error loading .env file:", err)
	}

	// --- START: 配置日志输出到文件 (根据环境变量控制) ---
	enableFileLogging := getEnvAsBool("ENABLE_FILE_LOGGING", false) // 默认不开启文件日志

	if enableFileLogging {
		logFile, err := os.OpenFile("devops.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening log file: %v", err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile) // 添加日期、时间、文件名和行号
		log.Println("File logging enabled: devops.log")
	} else {
		log.SetOutput(os.Stdout) // 默认输出到控制台
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
		log.Println("Console logging enabled.")
	}
	// --- END: 配置日志输出到文件 (根据环境变量控制) ---

	// 加载通用配置
	config.Secret = getEnv("WEBHOOK_SECRET", "")
	config.Port = getEnv("PORT", "8080")
	config.Applications = make(map[string]ApplicationConfig) // 初始化 map

	// --- START: 从 JSON 文件加载应用程序配置 ---
	jsonConfigPath := getEnv("APP_CONFIG_FILE", "config.json") // 配置文件路径，可从环境变量配置
	log.Printf("Loading application configuration from %s", jsonConfigPath)

	jsonFile, err := os.Open(jsonConfigPath)
	if err != nil {
		log.Fatalf("Error opening config file %s: %v", jsonConfigPath, err)
	}
	defer jsonFile.Close()

	byteValue, _ := io.ReadAll(jsonFile)

	var jsonConfig JsonConfigRoot
	if err := json.Unmarshal(byteValue, &jsonConfig); err != nil {
		log.Fatalf("Error unmarshalling config JSON: %v", err)
	}

	for _, appEntry := range jsonConfig.Applications {
		// 将 JSON 中的 name 规范化，与 Webhook 接收到的仓库名匹配
		appName := strings.ToLower(strings.ReplaceAll(appEntry.Name, ".", "_"))
		config.Applications[appName] = ApplicationConfig{
			RepoPath:          appEntry.Conf.RepoPath,
			DockerComposeFile: appEntry.Conf.DockerComposeFile,
			UseDockerCompose:  appEntry.Conf.UseDockerCompose,
			RepoBranch:        appEntry.Conf.RepoBranch,
			BuildBash:         appEntry.Conf.BuildBash, // 赋值新的字段
		}
		log.Printf("  Loaded app: %s (normalized to %s) with config: %+v", appEntry.Name, appName, config.Applications[appName])
	}
	log.Println("--- Finished application configuration loading from JSON ---")
	log.Printf("Loaded applications map: %+v", config.Applications) // 打印最终加载的应用程序配置
	// --- END: 从 JSON 文件加载应用程序配置 ---

	// 检查必要的配置
	if config.Secret == "" {
		log.Fatal("WEBHOOK_SECRET is required")
		return
	}
	if len(config.Applications) == 0 {
		log.Fatal("No application configuration found in JSON file")
		return
	}

	// 初始化应用程序状态
	for appName := range config.Applications {
		appStatusMap.Store(appName, "idle") // 初始状态为 "idle"
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Post("/webhook", handleWebhook)

	// --- START: 打印程序启动时的 $PATH 环境变量 ---
	log.Printf("Go program's PATH environment variable: %s", os.Getenv("PATH"))
	// --- END: 打印程序启动时的 $PATH 环境变量 ---

	log.Printf("Server listening on port %s\n", config.Port)
	if err := http.ListenAndServe(":"+config.Port, r); err != nil {
		log.Fatal(err)
	}
}

// handleWebhook 处理 Gogs 的 Webhook 请求
func handleWebhook(w http.ResponseWriter, r *http.Request) {
	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// 验证签名
	if !verifySignature(r, body, config.Secret) {
		log.Println("Signature verification failed")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 解析 Webhook 数据
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	repository, ok := payload["repository"].(map[string]interface{})
	if !ok {
		log.Println("repository field not found in Webhook payload")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	repoName, ok := repository["name"].(string)
	if !ok {
		log.Println("repository.name field not found in Webhook payload")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 从 payload 中获取分支信息
	ref, ok := payload["ref"].(string)
	if !ok {
		log.Println("ref field not found in Webhook payload, cannot determine branch.")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	// Gogs 的 ref 格式通常是 "refs/heads/master" 或 "refs/tags/v1.0"
	// 我们只关心分支，所以提取 "master" 部分
	branchName := strings.TrimPrefix(ref, "refs/heads/")
	log.Printf("Received push to branch: %s for repository: %s", branchName, repoName)


	// 将仓库名称转换为小写，并将点号替换为下划线，以匹配 JSON 中的命名约定
	appName := strings.ToLower(strings.ReplaceAll(repoName, ".", "_"))

	// 获取应用程序配置
	appConfig, ok := config.Applications[appName]
	if !ok {
		log.Printf("No configuration found for repository: %s (normalized to %s)", repoName, appName)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// --- START: 检查分支是否匹配 ---
	if appConfig.RepoBranch != "" && appConfig.RepoBranch != branchName {
		log.Printf("Configured branch '%s' for app '%s' does not match pushed branch '%s'. Ignoring build.",
			appConfig.RepoBranch, appName, branchName)
		w.Write([]byte("OK")) // 仍然返回 200 OK
		return
	}
	log.Printf("Branch '%s' matches configured branch '%s' (or no specific branch configured). Proceeding.",
		branchName, appConfig.RepoBranch)
	// --- END: 检查分支是否匹配 ---


	// 获取应用程序状态
	status, ok := appStatusMap.Load(appName)
	if !ok {
		status = "idle" // 默认状态
		appStatusMap.Store(appName, status)
	}

	// 检查应用程序状态
	if status == "building" {
		log.Printf("Application %s is currently building, ignoring this request", appName)
		w.Write([]byte("OK")) // 仍然返回 200 OK，避免 Gogs 重复发送
		return
	}

	// 设置应用程序状态为 "building"
	appStatusMap.Store(appName, "building")
	log.Printf("Application %s status set to building", appName)

	// 异步执行构建操作
	go func() {
		defer func() {
			// 在构建完成后，将应用程序状态设置为 "idle"
			appStatusMap.Store(appName, "idle")
			log.Printf("Application %s status set to idle", appName)
		}()

		log.Printf("Handling Webhook for repository: %s", repoName)

		// 执行拉取代码和构建的命令
		// 传递 buildBash 参数
		if err := updateAndBuild(appConfig.RepoPath, branchName, appConfig.BuildBash); err != nil {
			log.Printf("Error updating and building: %v", err)
			//  这里不要直接返回错误，因为是在 goroutine 中执行，
			//  无法直接影响到 http.ResponseWriter
			return
		}

		// 如果配置了 Docker Compose，则重启容器
		if appConfig.UseDockerCompose {
			if err := restartContainer(appConfig.DockerComposeFile); err != nil {
				log.Printf("Error restarting container: %v", err)
				//  同上，不要直接返回错误
				return
			}
		}
	}()

	w.Write([]byte("OK"))
}

// updateAndBuild 拉取代码并构建
// 增加了 branchToPull 参数，用于指定要拉取的分支
// 增加了 buildBash 参数，用于执行自定义构建命令
func updateAndBuild(repoPath string, branchToPull string, buildBash string) error {
	log.Println("Updating and building...")

	// --- START: 显式指定 git 命令的完整路径 ---
	gitPath := "/usr/bin/git" // 根据 which git 的输出，使用完整路径
	// --- END: 显式指定 git 命令的完整路径 ---

	// --- NEW: 检查 git 可执行文件是否存在和可执行 ---
	gitFileInfo, err := os.Stat(gitPath)
	if os.IsNotExist(err) {
		log.Printf("ERROR: Git executable not found at %s: %v", gitPath, err)
		return fmt.Errorf("git executable not found at %s: %w", gitPath, err)
	}
	if err != nil {
		log.Printf("ERROR: Error checking git executable at %s: %v", gitPath, err)
		return fmt.Errorf("error checking git executable at %s: %w", gitPath, err)
	}
	if !gitFileInfo.Mode().IsRegular() {
		log.Printf("ERROR: %s is not a regular file", gitPath)
		return fmt.Errorf("%s is not a regular file", gitPath)
	}
	if gitFileInfo.Mode().Perm()&0111 == 0 { // Check if any execute bit is set
		log.Printf("ERROR: %s is not executable by current user/group/others (permissions: %o)", gitPath, gitFileInfo.Mode().Perm())
		return fmt.Errorf("%s is not executable", gitPath)
	}
	log.Printf("Verified git executable at %s exists and is runnable.", gitPath)
	// --- END NEW ---

	// 切换到指定分支 (如果需要)
	log.Printf("Executing command: %s %v in directory: %s", gitPath, []string{"checkout", branchToPull}, repoPath) // DEBUG: 打印完整命令
	checkoutCmd := exec.Command(gitPath, "checkout", branchToPull) // 使用完整路径
	checkoutCmd.Dir = repoPath
	output, err := checkoutCmd.CombinedOutput()
	if err != nil {
		log.Printf("git checkout output: %s", output)
		return fmt.Errorf("%s checkout %s failed: %w, output: %s", gitPath, branchToPull, err, output)
	}
	log.Printf("git checkout output: %s", output)


	// 使用 git pull 拉取最新代码
	log.Printf("Executing command: %s %v in directory: %s", gitPath, []string{"pull"}, repoPath) // DEBUG: 打印完整命令
	cmd := exec.Command(gitPath, "pull") // 使用完整路径
	cmd.Dir = repoPath // 设置工作目录
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("git pull output: %s", output)
		return fmt.Errorf("%s pull failed: %w, output: %s", gitPath, err, output)
	}
	log.Printf("git pull output: %s", output)

	// --- START: 执行自定义构建命令 ---
	if buildBash != "" {
		log.Printf("Executing custom build command: '%s' in directory: %s", buildBash, repoPath)
		buildCmd := exec.Command("sh", "-c", buildBash) // 使用 sh -c 来执行自定义命令
		buildCmd.Dir = repoPath
		output, err = buildCmd.CombinedOutput()
		if err != nil {
			log.Printf("Build output: %s", output)
			return fmt.Errorf("build failed: %w, output: %s", err, output)
		}
		log.Printf("Build output: %s", output)
		log.Println("Custom build command executed successfully.")
	} else {
		log.Println("No custom build command specified. Skipping build step.")
	}
	// --- END: 执行自定义构建命令 ---

	log.Println("Update and build successful")
	return nil
}

// restartContainer 重启 Docker 容器
func restartContainer(dockerComposeFile string) error {
	log.Println("Restarting container...")
	// 使用 docker-compose 重启服务
	cmd := exec.Command("docker-compose", "-f", dockerComposeFile, "up", "-d")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("docker-compose output: %s", output)
		return fmt.Errorf("docker-compose up -d failed: %w", err)
	}
	log.Printf("docker-compose output: %s", output)
	log.Println("Container restarted successfully")
	return nil
}

// verifySignature 验证 Gogs Webhook 的签名
func verifySignature(r *http.Request, body []byte, secret string) bool {
	//  Gogs 似乎没有提供标准的签名算法，这里需要根据 Gogs 的实际情况来做
	//  以下代码仅为示例，你需要替换为正确的签名验证逻辑
	//  例如，如果 Gogs 使用 HMAC-SHA256，你需要实现类似下面的逻辑：
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
	//  **请注意：你需要根据 Gogs 的官方文档来确定正确的签名验证方法。**
	//
	//  这里为了演示，简化处理，直接返回 true，**这非常不安全，不要在生产环境中使用**
	return true //  **这非常不安全，不要在生产环境中使用**
}

// getEnv 从环境变量中获取配置，如果不存在则使用默认值
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvAsBool 从环境变量中获取布尔值
func getEnvAsBool(key string, defaultValue bool) bool {
    valueStr := os.Getenv(key)
    if valueStr == "" {
        return defaultValue
    }
    value := strings.ToLower(valueStr)
    return value == "true" || value == "1"
}
