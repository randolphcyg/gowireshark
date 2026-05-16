package version

// Version 是项目版本（编译时通过 ldflags 注入）
var (
	Version   string = "1.0.0"
	GitCommit string = "unknown"
	BuildTime string = "unknown"
)

// GetVersion 返回完整版本信息
func GetVersion() string {
	return Version
}

// GetFullInfo 返回包含 Git 提交和构建时间的完整信息
func GetFullInfo() string {
	return Version + "-" + GitCommit + " (" + BuildTime + ")"
}

// GetMajorVersion 返回主版本号
func GetMajorVersion() string {
	for i, c := range Version {
		if c == '.' {
			return Version[:i]
		}
	}
	return Version
}
