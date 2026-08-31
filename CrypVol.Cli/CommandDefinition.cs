using System.CommandLine;
using System.IO.Compression;
using CrypVol.Cli.Browse;
using CrypVol.Cli.Convert;
using CrypVol.Cli.Extract;
using CrypVol.Cli.GenKey;
using CrypVol.Cli.Info;
using CrypVol.Cli.Pack;
using CrypVol.Cli.Rekey;
using CrypVol.Cli.Repair;
using CrypVol.Cli.Verify;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Volume;
using Microsoft.Extensions.Logging;

namespace CrypVol.Cli;

/// <summary>
///     CrypVol CLI 完整的命令树定义
/// </summary>
public static class CommandDefinition
{
    // ═══════════════════════════════════════════════════════════════
    //  全局选项
    // ═══════════════════════════════════════════════════════════════

    /// <summary>日志级别（全局可用）。默认 Information；-v &lt;level&gt; 覆盖级别。</summary>
    public static readonly Option<LogLevel> Verbose = new("--verbose", "-v")
    {
        Description =
            """
            输出详细日志。可指定级别：
              （无参数）   → Information（默认级别）
              -v Info      → 信息
              -v Debug     → 调试信息
              -v Trace     → 最详细（含管道逐块追踪）
              -v Warning   → 仅警告和错误
              -v Error     → 仅错误
            """,
        Arity = ArgumentArity.ZeroOrOne,
        HelpName = "level",
        Recursive = true,
        DefaultValueFactory = static _ => LogLevel.Information
    };

    // ═══════════════════════════════════════════════════════════════
    //  根命令
    // ═══════════════════════════════════════════════════════════════

    public static RootCommand BuildCommand()
    {
        var root = new RootCommand(
            """
            CrypVol —— 加密分卷归档工具 (Cryptographic Volume Package)

            将文件或目录打包为带加密保护的 .cvp 数据卷，支持分卷存储、
            多层密钥保护，并可从卷中提取、浏览、校验数据。
            """)
        {
            Verbose,
            GenKey.SubCommand(),
            Pack.SubCommand(),
            Extract.SubCommand(),
            Browse.SubCommand(),
            Info.SubCommand(),
            Verify.SubCommand(),
            Repair.SubCommand(),
            Rekey.SubCommand(),
            Convert.SubCommand()
        };

        return root;
    }

    // ═══════════════════════════════════════════════════════════════
    //  pack — 打包
    // ═══════════════════════════════════════════════════════════════

    public static class Pack
    {
        // ── 参数 ──
        public static readonly Argument<FileSystemInfo> InputPath;

        // ── 选项 ──
        public static readonly Option<DirectoryInfo> OutputPath;
        public static readonly Option<string> OutputPrefix;
        public static readonly Option<uint> VolumeSize;
        public static readonly Option<uint> ChunkSize;
        public static readonly Option<FileInfo> KeyFile;
        public static readonly Option<EncryptionMode> Mode;
        public static readonly Option<string> Password;
        public static readonly Option<IEnumerable<FileInfo>> PublicKey;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;
        public static readonly Option<bool> Compress;
        public static readonly Option<CompressionLevel> CompressionLevel;
        public static readonly Option<bool> NoCompress;
        public static readonly Option<DirectoryInfo> KeyOutputPath;
        public static readonly Option<string> Include;
        public static readonly Option<string> Exclude;
        public static readonly Option<IntegrityLevel> Integrity;
        public static readonly Option<bool> DryRun;
        public static readonly Option<string> Comment;

        static Pack()
        {
            // ── 参数 ──
            InputPath = new Argument<FileSystemInfo>("path")
            {
                Description = "要打包的源路径 —— 可以是文件或目录，打包时保留相对路径结构"
            }.AcceptExistingOnly();

            // ── 输出选项 ──
            OutputPath = new Option<DirectoryInfo>("--output", "-o")
            {
                Description = "输出文件目录。生成的 .cvp 卷文件及 .cvk 密钥文件将写入此目录",
                HelpName = "dir",
                DefaultValueFactory = static result =>
                {
                    var input = result.GetValue(InputPath);
                    return input switch
                    {
                        FileInfo fi => fi.Directory!,
                        DirectoryInfo di => di,
                        _ => null!
                    };
                }
            }.AcceptLegalFilePathsOnly();

            OutputPrefix = new Option<string>("--output-prefix", "--prefix")
            {
                Description =
                    """
                    输出文件名前缀。
                    卷文件命名格式：<前缀>.<卷号>.cvp
                    密钥文件命名格式：<前缀>.cvk
                    """,
                HelpName = "name",
                DefaultValueFactory = static result =>
                {
                    var input = result.GetValue(InputPath);
                    return input switch
                    {
                        FileInfo fi => Path.GetFileNameWithoutExtension(fi.Name) is { Length: > 0 } name
                            ? name
                            : fi.Directory?.Name ?? "archive",
                        DirectoryInfo di => di.Name,
                        _ => "archive"
                    };
                }
            };

            // ── 卷选项 ──
            VolumeSize = new Option<uint>("--volume-size", "-s")
            {
                Description = "生成时的近似卷切分目标（单位：MiB）。卷格式与读取流程不依赖此值",
                HelpName = "mib",
                DefaultValueFactory = static _ => 1024u
            };

            ChunkSize = new Option<uint>("--chunk-size")
            {
                Description = "单次读取与处理的数据块大小（单位：MiB，范围 1–64）。较大值通常压缩率更高，但占用更多内存",
                HelpName = "mib",
                DefaultValueFactory = static _ => 16u
            };

            // ── 加密选项：两种模式互斥 ──
            //   A) 指定 --key-file → 复用已有 .cvk 的 CEK（--mode/--public-key 忽略）
            //   B) 不指定       → 生成新 CEK + 新 .cvk（--mode 等必需）

            KeyFile = new Option<FileInfo>("--key-file", "-k")
            {
                Description =
                    """
                    指定已有 .cvk 密钥文件，直接使用其 CEK 加密数据。
                    Password 模式的 CVK 仍须通过 --password 解封；Asymmetric 模式须提供 --privkey-key。
                    提供此选项时，--mode / --public-key / --comment 不参与新密钥创建。
                    不提供时，需通过 --mode 等选项配置新密钥的生成方式。
                    """,
                HelpName = "cvk-file"
            }.AcceptExistingOnly();

            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = "解密已有 .cvk 的私钥（Asymmetric 模式，与 --key-file 配合）",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件的解密密码（若私钥自身加密）",
                HelpName = "passphrase"
            };

            Mode = new Option<EncryptionMode>("--mode", "-m")
            {
                Description =
                    """
                    新密钥的保护模式（未指定 --key-file 时生效）：

                    None       —— 不加密，不生成 .cvk 文件
                    PlainKey   —— CEK 明文存储在 .cvk 中（默认）
                    Password   —— CEK 经 Argon2id + AES-256-GCM 加密，需密码解密
                    Asymmetric —— CEK 经 RSA 公钥加密，需对应私钥解密
                    """,
                DefaultValueFactory = static _ => EncryptionMode.PlainKey
            };

            Password = new Option<string>("--password", "-p")
            {
                Description =
                    """
                    新密钥的加密密码。仅在未指定 --key-file 且 --mode Password 时生效。
                    建议使用 12 位以上的强密码。
                    """,
                HelpName = "passphrase"
            };

            PublicKey = new Option<IEnumerable<FileInfo>>("--public-key")
            {
                Description =
                    """
                    RSA 公钥文件（PEM 格式）。仅在未指定 --key-file 且 --mode Asymmetric 时生效。
                    可多次指定以支持多个接收者。
                    KeyID 默认为文件名（不含扩展名），用于标识密钥。
                    """,
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            // ── 压缩选项 ──
            Compress = new Option<bool>("--compress", "-c")
            {
                Description = "启用 GZip 数据压缩（默认已启用；保留此选项以兼容旧脚本）",
                DefaultValueFactory = static _ => true
            };

            NoCompress = new Option<bool>("--no-compress")
            {
                Description = "禁用 GZip 数据压缩"
            };

            CompressionLevel = new Option<CompressionLevel>("--compression-level")
            {
                Description =
                    """
                    GZip 压缩预设：Fastest、Optimal、SmallestSize。
                    默认 Optimal；仅在未指定 --no-compress 时生效。
                    """,
                HelpName = "preset",
                DefaultValueFactory = static _ => System.IO.Compression.CompressionLevel.Optimal
            };

            // ── 密钥输出 ──
            KeyOutputPath = new Option<DirectoryInfo>("--key-output")
            {
                Description = "单独指定 .cvk 密钥文件的输出目录。未指定时与 --output 相同",
                HelpName = "dir",
                DefaultValueFactory = static result => result.GetValue(OutputPath)!
            }.AcceptLegalFilePathsOnly();

            // ── 过滤选项 ──
            Include = new Option<string>("--include")
            {
                Description = "仅打包匹配该 Glob 模式的文件",
                HelpName = "pattern"
            };

            Exclude = new Option<string>("--exclude")
            {
                Description = "排除匹配 Glob 模式的文件。常见用法：--exclude \"**/node_modules/**\"",
                HelpName = "pattern"
            };

            // ── 完整性 ──
            Integrity = new Option<IntegrityLevel>("--integrity")
            {
                Description =
                    """
                    块级数据完整性校验：

                    None  —— 不嵌入校验数据
                    Block —— 每个数据块附带 CRC32（默认），可检测磁盘静默损坏
                    File  —— 每个文件附带 SHA-256 校验值
                    Volume —— 每个卷附带 SHA-256 校验值（含块级校验）
                    """,
                DefaultValueFactory = static _ => IntegrityLevel.Block
            };

            // ── 预览 ──
            DryRun = new Option<bool>("--dry-run")
            {
                Description =
                    """
                    预估模式：不写入数据或密钥文件，仅按原始大小和块大小给出近似卷数与块数。
                    压缩、加密和动态卷路由会使实际结果不同。
                    """
            };

            // ── 备注 ──
            Comment = new Option<string>("--comment")
            {
                Description = "在密钥文件中嵌入一段备注文字（例如版本号、用途说明）",
                HelpName = "text"
            };
        }

        public static Command SubCommand()
        {
            var cmd = new Command("pack",
                """
                将文件或目录打包为加密卷 (.cvp) 并生成对应的密钥文件 (.cvk)。

                示例：
                  crypvol pack ./docs -m Password -p "secret123"
                  crypvol pack ./photos -s 2048 --include "**/*.jpg"
                  crypvol pack ./data -m Asymmetric --public-key alice.pem
                  crypvol pack ./archive --dry-run
                """)
            {
                InputPath,
                OutputPath,
                OutputPrefix,
                VolumeSize,
                ChunkSize,
                KeyFile,
                Mode,
                Password,
                PublicKey,
                PrivkeyKey,
                PrivkeyKeyPass,
                Compress,
                NoCompress,
                CompressionLevel,
                KeyOutputPath,
                Include,
                Exclude,
                Integrity,
                DryRun,
                Comment
            };

            cmd.SetAction(PackHelper.Invoker);
            return cmd;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  extract — 解包还原
    // ═══════════════════════════════════════════════════════════════

    public static class Extract
    {
        public static readonly Argument<ICollection<FileSystemInfo>> VolFiles;
        public static readonly Option<DirectoryInfo> Output;
        public static readonly Option<FileInfo> KeyFile;
        public static readonly Option<string> Password;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;
        public static readonly Option<string> Include;
        public static readonly Option<string> Exclude;
        public static readonly Option<bool> Overwrite;

        static Extract()
        {
            VolFiles = new Argument<ICollection<FileSystemInfo>>("cvp")
            {
                Description =
                    """
                    一个或多个 .cvp 数据卷文件路径。
                    只需提供组内的任意一个 .cvp，程序会自动发现同目录同前缀的其他卷。
                    可同时指定多组卷（不同前缀/目录），将分别解包。
                    """,
                Arity = ArgumentArity.OneOrMore
            }.AcceptExistingOnly();

            Output = new Option<DirectoryInfo>("--output", "-o")
            {
                Description = "目标还原目录。未指定时使用卷文件所在目录",
                HelpName = "dir",
                DefaultValueFactory = static result =>
                {
                    var input = result.GetValue(VolFiles)?.FirstOrDefault();
                    return input switch
                    {
                        FileInfo fi => fi.Directory!,
                        DirectoryInfo di => di,
                        _ => new DirectoryInfo(Directory.GetCurrentDirectory())
                    };
                }
            }.AcceptLegalFilePathsOnly();

            KeyFile = new Option<FileInfo>("--key-file", "-k")
            {
                Description = "对应的 .cvk 密钥文件路径。程序会自动搜索同目录同名 .cvk，仅在需要指定不同路径时使用",
                HelpName = "cvk-file"
            }.AcceptExistingOnly();

            Password = new Option<string>("--password", "-p")
            {
                Description = "密钥文件解密密码（Password 模式必需）",
                HelpName = "passphrase"
            };

            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = "RSA 私钥文件路径（Asymmetric 模式必需）",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件本身的解密密码（仅私钥文件本身受密码保护时需要）",
                HelpName = "passphrase"
            };

            Include = new Option<string>("--include")
            {
                Description = "仅提取匹配 Glob 模式的文件",
                HelpName = "pattern"
            };

            Exclude = new Option<string>("--exclude")
            {
                Description = "排除匹配 Glob 模式的文件",
                HelpName = "pattern"
            };

            Overwrite = new Option<bool>("--overwrite")
            {
                Description = "覆盖目标目录中已存在的同名文件。未指定时遇到同名文件会跳过并警告"
            };
        }

        public static Command SubCommand()
        {
            var cmd = new Command("extract",
                """
                从数据卷 (.cvp) 中还原文件。

                只需提供任意一个卷文件，程序自动发现同组所有卷。
                支持 Glob 过滤和覆盖控制。

                示例：
                  crypvol extract ./archive.1.cvp
                    自动发现同组卷并还原到当前目录

                  crypvol extract ./data.1.cvp -p "secret123" -o ./restored --overwrite
                    用密码解密，提取到指定目录，覆盖已存在文件

                  crypvol extract ./vol.1.cvp --privkey-key ./mykey.pem --include "**/*.docx"
                    用私钥解密，仅提取 Word 文档
                """)
            {
                VolFiles,
                Output,
                KeyFile,
                Password,
                PrivkeyKey,
                PrivkeyKeyPass,
                Include,
                Exclude,
                Overwrite
            };

            cmd.SetAction(ExtractHelper.Invoker);
            return cmd;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  browse — 浏览卷内容
    // ═══════════════════════════════════════════════════════════════

    public static class Browse
    {
        public static readonly Argument<ICollection<FileSystemInfo>> VolFiles;
        public static readonly Option<bool> LongFormat;
        public static readonly Option<FileInfo> KeyFile;
        public static readonly Option<string> Password;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;
        public static readonly Option<string> Include;
        public static readonly Option<string> Exclude;
        public static readonly Option<OutputFormat> OutputFormat;
        public static readonly Option<FileInfo> Output;

        static Browse()
        {
            VolFiles = new Argument<ICollection<FileSystemInfo>>("cvp")
            {
                Description =
                    """
                    一个或多个 .cvp 数据卷文件路径。
                    只需提供组内的任意一个 .cvp，程序会自动发现同目录同前缀的其他卷。
                    """,
                Arity = ArgumentArity.OneOrMore
            }.AcceptExistingOnly();

            LongFormat = new Option<bool>("--long", "-l")
            {
                Description =
                    """
                    详细信息模式：
                    Table  —— 增加跨卷链列
                    List   —— 显示文件大小、片段数、卷号
                    Json   —— 增加 CrossVolume、VolumeSpan 字段
                    Csv    —— 增加 CrossVolume、VolumeSpan 列
                    """
            };

            KeyFile = new Option<FileInfo>("--key-file", "-k")
            {
                Description = "对应的 .cvk 密钥文件路径。仅在加密卷需要解密才能读取元数据时使用",
                HelpName = "cvk-file"
            }.AcceptExistingOnly();

            Password = new Option<string>("--password", "-p")
            {
                Description = "密钥文件解密密码",
                HelpName = "passphrase"
            };

            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = "RSA 私钥文件路径",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件本身的密码（若私钥加密）",
                HelpName = "passphrase"
            };

            Include = new Option<string>("--include")
            {
                Description = "仅列出匹配 Glob 模式的文件",
                HelpName = "pattern"
            };

            Exclude = new Option<string>("--exclude")
            {
                Description = "隐藏匹配 Glob 模式的文件",
                HelpName = "pattern"
            };

            OutputFormat = new Option<OutputFormat>("--format", "-f")
            {
                Description = "输出格式：List（简洁列表）、Table（对齐表格）、Json、Csv",
                HelpName = "fmt",
                DefaultValueFactory = static _ => Cli.OutputFormat.List
            };

            Output = new Option<FileInfo>("--output", "-o")
            {
                Description = "将输出写入文件而非控制台",
                HelpName = "path"
            };
        }

        public static Command SubCommand()
        {
            var cmd = new Command("browse",
                """
                列出数据卷 (.cvp) 中的文件清单，无需完整解包。

                支持四种输出格式：List（简洁列表）、Table（对齐表格）、Json、Csv。
                加密卷需提供密钥文件才能读取元数据。

                示例：
                  crypvol browse ./archive.1.cvp
                    默认列表格式

                  crypvol browse ./archive.1.cvp -f Table -l
                    表格格式 + 跨卷详情

                  crypvol browse ./archive.1.cvp -f Json -o files.json
                    导出为 JSON 文件

                  crypvol browse ./archive.1.cvp --include "**/*.jpg"
                    仅列出匹配的文件
                """)
            {
                VolFiles,
                LongFormat,
                OutputFormat,
                Output,
                KeyFile,
                Password,
                PrivkeyKey,
                PrivkeyKeyPass,
                Include,
                Exclude
            };

            cmd.SetAction(BrowseHelper.Invoker);
            return cmd;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  info — 密钥文件信息
    // ═══════════════════════════════════════════════════════════════

    public static class Info
    {
        public static readonly Argument<FileInfo> KeyFile;
        public static readonly Option<string> Password;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;

        static Info()
        {
            KeyFile = new Argument<FileInfo>("cvk")
            {
                Description = ".cvk 密钥文件路径"
            }.AcceptExistingOnly();

            Password = new Option<string>("--password", "-p")
            {
                Description = "密钥文件解密密码。成功解封后显示 CEK 指纹、注释等内容",
                HelpName = "passphrase"
            };

            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = "RSA 私钥文件路径。提供后将尝试验证并显示额外信息",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件本身的密码",
                HelpName = "passphrase"
            };
        }

        public static Command SubCommand()
        {
            var cmd = new Command("info",
                """
                显示密钥文件 (.cvk) 的信封编码模式；成功解封后显示 CEK 指纹、注释和公钥接收者。
                即使未提供解封凭据也会输出信封模式，但 Password 或 Asymmetric CVK 将以失败退出。

                示例：
                  crypvol info ./archive.cvk
                    验证明文密钥文件

                  crypvol info ./archive.cvk -p "secret123"
                    验证密码并展示 CEK 指纹
                """)
            {
                KeyFile,
                Password,
                PrivkeyKey,
                PrivkeyKeyPass
            };

            cmd.SetAction(InfoHelper.Invoker);
            return cmd;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  verify — 完整性校验
    // ═══════════════════════════════════════════════════════════════

    public static class Verify
    {
        public static readonly Argument<ICollection<FileSystemInfo>> VolFiles;
        public static readonly Option<FileInfo> KeyFile;
        public static readonly Option<string> Password;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;
        public static readonly Option<string> Include;
        public static readonly Option<string> Exclude;
        public static readonly Option<bool> Quick;
        public static readonly Option<FileInfo?> RepairReport;

        static Verify()
        {
            VolFiles = new Argument<ICollection<FileSystemInfo>>("cvp")
            {
                Description =
                    """
                    一个或多个 .cvp 数据卷文件路径。
                    只需提供组内的任意一个 .cvp，程序会自动扫描同组所有卷。
                    """,
                Arity = ArgumentArity.OneOrMore
            }.AcceptExistingOnly();

            KeyFile = new Option<FileInfo>("--key-file", "-k")
            {
                Description = "对应的 .cvk 密钥文件路径。程序会自动搜索同目录同名 .cvk",
                HelpName = "cvk-file"
            }.AcceptExistingOnly();

            Password = new Option<string>("--password", "-p")
            {
                Description = "密钥文件解密密码",
                HelpName = "passphrase"
            };

            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = "RSA 私钥文件路径",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件本身的密码",
                HelpName = "passphrase"
            };

            Include = new Option<string>("--include")
            {
                Description = "仅校验匹配 Glob 模式的文件",
                HelpName = "pattern"
            };

            Exclude = new Option<string>("--exclude")
            {
                Description = "跳过匹配 Glob 模式的文件（不校验）",
                HelpName = "pattern"
            };

            Quick = new Option<bool>("--quick")
            {
                Description =
                    """
                    快速模式：仅校验卷文件头和元数据结构（不读取全部数据）。
                    适用于快速检查卷是否可识别，但无法检测数据块级损坏。
                    """
            };

            RepairReport = new Option<FileInfo?>("--repair-report", "-r")
            {
                Description =
                    """
                    生成损坏块/文件报告并写入指定文件。
                    该报告可作为 repair 命令的输入，精确定位需要修复的数据区域。
                    """,
                HelpName = "file"
            }.AcceptLegalFilePathsOnly();
        }

        public static Command SubCommand()
        {
            var cmd = new Command("verify",
                """
                校验数据卷 (.cvp) 的完整性和数据一致性。

                逐块验证 CRC32 校验值，报告数据损坏或缺失。
                可生成损坏报告供 repair 命令使用。

                退出码：0 = 完整无损坏，1 = 检测到损坏，2 = 无法读取/致命错误

                示例：
                  crypvol verify ./archive.1.cvp
                    校验所有卷，报告损坏情况

                  crypvol verify ./archive.1.cvp --quick
                    快速检查卷头结构完整性

                  crypvol verify ./archive.1.cvp -r damage-report.txt
                    校验并生成损坏报告
                """)
            {
                VolFiles,
                KeyFile,
                Password,
                PrivkeyKey,
                PrivkeyKeyPass,
                Include,
                Exclude,
                Quick,
                RepairReport
            };

            cmd.SetAction(VerifyHelper.Invoker);
            return cmd;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  repair — 修复损坏的卷
    // ═══════════════════════════════════════════════════════════════

    public static class Repair
    {
        public static readonly Argument<ICollection<FileSystemInfo>> VolFiles;
        public static readonly Option<DirectoryInfo> Output;
        public static readonly Option<FileInfo> KeyFile;
        public static readonly Option<string> Password;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;
        public static readonly Option<bool> Backup;
        public static readonly Option<FileInfo> VerifyReport;

        static Repair()
        {
            VolFiles = new Argument<ICollection<FileSystemInfo>>("cvp")
            {
                Description =
                    """
                    需要修复的 .cvp 数据卷文件路径。
                    只需提供组内的任意一个 .cvp，程序会自动处理同组所有卷。
                    """,
                Arity = ArgumentArity.OneOrMore
            }.AcceptExistingOnly();

            Output = new Option<DirectoryInfo>("--output", "-o")
            {
                Description = "修复后文件的输出目录。未指定时在原位置修复（建议配合 --backup 使用）",
                HelpName = "dir",
                DefaultValueFactory = static result =>
                {
                    var input = result.GetValue(VolFiles)?.FirstOrDefault();
                    return input switch
                    {
                        FileInfo fi => fi.Directory!,
                        DirectoryInfo di => di,
                        _ => new DirectoryInfo(Directory.GetCurrentDirectory())
                    };
                }
            }.AcceptLegalFilePathsOnly();

            KeyFile = new Option<FileInfo>("--key-file", "-k")
            {
                Description = "对应的 .cvk 密钥文件路径",
                HelpName = "cvk-file"
            }.AcceptExistingOnly();

            Password = new Option<string>("--password", "-p")
            {
                Description = "密钥文件解密密码",
                HelpName = "passphrase"
            };

            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = "RSA 私钥文件路径",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件本身的密码",
                HelpName = "passphrase"
            };

            Backup = new Option<bool>("--backup", "-b")
            {
                Description =
                    """
                    在修复前为每个原始卷创建 .bak 备份文件。
                    强烈建议在首次修复不熟悉的卷时使用。
                    """
            };

            VerifyReport = new Option<FileInfo>("--verify-report")
            {
                Description =
                    """
                    从 verify 命令生成的损坏报告文件中读取精确定位信息，
                    仅修复报告中标记的损坏区域，加快修复速度。
                    """,
                HelpName = "file"
            }.AcceptExistingOnly();
        }

        public static Command SubCommand()
        {
            var cmd = new Command("repair",
                """
                修复损坏的 .cvp 数据卷。

                定位并零填充无法恢复的损坏块，写入有效 CRC32 以保持卷结构完整。
                建议配合 --backup 在修复前备份原始文件。

                示例：
                  crypvol repair ./archive.1.cvp --backup
                    修复前备份原文件，在原位置生成修复后的卷

                  crypvol repair ./archive.1.cvp -o ./fixed
                    修复并输出到指定目录

                  crypvol repair ./archive.1.cvp --verify-report damage-report.txt
                    根据校验报告精确修复
                """)
            {
                VolFiles,
                Output,
                KeyFile,
                Password,
                PrivkeyKey,
                PrivkeyKeyPass,
                Backup,
                VerifyReport
            };

            cmd.SetAction(RepairHelper.Invoker);
            return cmd;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  rekey — 重新封装密钥信封
    // ═══════════════════════════════════════════════════════════════

    public static class Rekey
    {
        public static readonly Argument<FileInfo> CvkFile;
        public static readonly Option<string> Password;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;
        public static readonly Option<FileInfo?> Output;
        public static readonly Option<EncryptionMode> ToMode;
        public static readonly Option<string> NewPassword;
        public static readonly Option<IEnumerable<FileInfo>> PublicKey;
        public static readonly Option<bool> Backup;

        static Rekey()
        {
            CvkFile = new Argument<FileInfo>("cvk")
            {
                Description = "要重新封装的 .cvk 密钥文件路径"
            }.AcceptExistingOnly();

            Output = new Option<FileInfo?>("--output", "-o")
            {
                Description = "重新封装后的 .cvk 输出路径。未指定时覆盖源文件",
                HelpName = "file"
            }.AcceptLegalFilePathsOnly();

            ToMode = new Option<EncryptionMode>("--to-mode")
            {
                Description =
                    """
                    目标密钥保护模式：

                    PlainKey   —— 将 CEK 以明文存储（降低安全性）
                    Password   —— 用密码包裹 CEK
                    Asymmetric —— 用公钥包裹 CEK
                    （必需指定）
                    """
            };

            Password = new Option<string>("--password", "-p")
            {
                Description = "当前 .cvk 的解密密码（当前为 Password 模式时必需）",
                HelpName = "passphrase"
            };

            NewPassword = new Option<string>("--new-password")
            {
                Description = "新的加密密码（转为 Password 模式时必需）",
                HelpName = "passphrase"
            };

            PublicKey = new Option<IEnumerable<FileInfo>>("--public-key")
            {
                Description = "新的公钥文件（转为 Asymmetric 模式时必需）",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = "当前 .cvk 的解密私钥（当前为 Asymmetric 模式时必需）",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "当前私钥文件的密码",
                HelpName = "passphrase"
            };

            Backup = new Option<bool>("--backup", "-b")
            {
                Description = "操作前备份原始 .cvk 文件（追加 .bak 后缀）"
            };
        }

        public static Command SubCommand()
        {
            var cmd = new Command("rekey",
                """
                重新封装 .cvk 密钥文件的保护方式。

                CEK 不变，仅更换密钥信封的保护层。不读取 .cvp 数据卷。
                例如将明文密钥改为密码保护，或将密码保护切换为公钥保护。

                示例：
                  crypvol rekey ./archive.cvk --to-mode Password --new-password "betterpass" -b
                    将 .cvk 转为密码保护（先备份原文件）

                  crypvol rekey ./archive.cvk --to-mode Asymmetric --public-key alice.pem -o ./new.cvk
                    将 .cvk 转为公钥保护，输出到新文件
                """)
            {
                CvkFile,
                Output,
                ToMode,
                Password,
                NewPassword,
                PublicKey,
                PrivkeyKey,
                PrivkeyKeyPass,
                Backup
            };

            cmd.SetAction(RekeyHelper.Invoker);
            return cmd;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  convert — 块级密钥轮换
    // ═══════════════════════════════════════════════════════════════

    public static class Convert
    {
        public static readonly Argument<ICollection<FileSystemInfo>> VolFiles;

        public static readonly Option<FileInfo> OldKeyFile;
        public static readonly Option<string> OldPassword;
        public static readonly Option<FileInfo> OldPrivkey;
        public static readonly Option<string> OldPrivkeyPass;

        public static readonly Option<DirectoryInfo> Output;
        public static readonly Option<string> OutputPrefix;

        public static readonly Option<FileInfo> KeyFile;
        public static readonly Option<string> Password;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;

        public static readonly Option<bool> Backup;


        static Convert()
        {
            VolFiles = new Argument<ICollection<FileSystemInfo>>("cvp")
            {
                Description =
                    """
                    一个或多个 .cvp 数据卷文件。
                    程序会发现当前目录中可见的同前缀卷；转换完整跨卷文件时应提供完整卷组。
                    """,
                Arity = ArgumentArity.OneOrMore
            }.AcceptExistingOnly();

            OldKeyFile = new Option<FileInfo>("--old-key-file", "-k")
            {
                Description = "当前 .cvk 密钥文件路径（程序自动搜索同目录同名 .cvk）",
                HelpName = "cvk-file"
            }.AcceptExistingOnly();

            OldPassword = new Option<string>("--old-password")
            {
                Description = "当前密钥文件的解密密码（Password 模式）",
                HelpName = "passphrase"
            };

            OldPrivkey = new Option<FileInfo>("--old-privkey-key")
            {
                Description = "当前密钥文件的解密私钥（Asymmetric 模式）",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            OldPrivkeyPass = new Option<string>("--old-key-pass")
            {
                Description = "当前私钥文件的密码",
                HelpName = "passphrase"
            };

            Output = new Option<DirectoryInfo>("--output", "-o")
            {
                Description = "新卷文件的输出目录",
                HelpName = "dir",
                DefaultValueFactory = static result =>
                {
                    var input = result.GetValue(VolFiles)?.FirstOrDefault();
                    return input switch
                    {
                        FileInfo fi => fi.Directory!,
                        DirectoryInfo di => di,
                        _ => new DirectoryInfo(Directory.GetCurrentDirectory())
                    };
                }
            }.AcceptLegalFilePathsOnly();

            OutputPrefix = new Option<string>("--output-prefix", "--prefix")
            {
                Description = "新卷文件的文件名前缀。未指定时使用 converted",
                HelpName = "name"
            };

            KeyFile = new Option<FileInfo>("--key-file")
            {
                Description =
                    """
                    目标 .cvk 密钥文件。其 CEK 将作为新加密密钥。
                    此命令仅支持重加密到已有 CVK，必须提供该参数。
                    """,
                HelpName = "cvk-file"
            }.AcceptExistingOnly();
            Password = new Option<string>("--password", "-p")
            {
                Description = "解封目标 --key-file 的密码（目标 CVK 为 Password 模式时必需）",
                HelpName = "passphrase"
            };

            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = "解封目标 --key-file 的私钥（目标 CVK 为 Asymmetric 模式时必需）",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "当前私钥文件的密码",
                HelpName = "passphrase"
            };

            Backup = new Option<bool>("--backup", "-b")
            {
                Description = "操作前备份原始 .cvp 文件（追加 .bak 后缀）"
            };
        }

        public static Command SubCommand()
        {
            var cmd = new Command("convert",
                """
                块级重加密：用旧 CEK 解密每个数据块，再用目标现有 CVK 的 CEK 重新加密。

                不解压、不还原文件，也不创建新的 CVK。读取流程不依赖生成时卷大小。

                典型场景：密钥轮换、为不同节点分发不同密钥域的数据。

                示例：
                  crypvol convert ./archive.1.cvp --old-key-file ./old.cvk --key-file ./new.cvk -o ./new
                    使用已有 new.cvk 的 CEK 重加密卷
                """)
            {
                VolFiles,
                OldKeyFile,
                OldPassword,
                OldPrivkey,
                OldPrivkeyPass,
                Output,
                OutputPrefix,
                KeyFile,
                Password,
                PrivkeyKey,
                PrivkeyKeyPass,
                Backup
            };

            cmd.SetAction(ConvertHelper.Invoker);
            return cmd;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  genkey — 生成密钥文件
    // ═══════════════════════════════════════════════════════════════

    public static class GenKey
    {
        public static readonly Option<DirectoryInfo> Output;
        public static readonly Option<string> Name;
        public static readonly Option<EncryptionMode> Mode;
        public static readonly Option<string> Password;
        public static readonly Option<IEnumerable<FileInfo>> PublicKey;
        public static readonly Option<string> Comment;

        static GenKey()
        {
            Output = new Option<DirectoryInfo>("--output", "-o")
            {
                Description = "输出目录（默认：当前目录）",
                HelpName = "dir",
                DefaultValueFactory = static _ => new DirectoryInfo(Directory.GetCurrentDirectory())
            }.AcceptLegalFilePathsOnly();

            Name = new Option<string>("--name", "-n")
            {
                Description = "密钥文件名（不含扩展名，默认：key）",
                HelpName = "name",
                DefaultValueFactory = static _ => "key"
            };

            Mode = new Option<EncryptionMode>("--mode", "-m")
            {
                Description =
                    """
                    密钥保护模式：
                    PlainKey   —— CEK 明文存储（默认）
                    Password   —— 密码包裹 CEK
                    Asymmetric —— 公钥包裹 CEK
                    """,
                DefaultValueFactory = static _ => EncryptionMode.PlainKey
            };

            Password = new Option<string>("--password", "-p")
            {
                Description = "加密 CEK 的密码（Password 模式必需）",
                HelpName = "passphrase"
            };

            PublicKey = new Option<IEnumerable<FileInfo>>("--public-key")
            {
                Description = "RSA 公钥 PEM 文件（Asymmetric 模式必需）",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            Comment = new Option<string>("--comment")
            {
                Description = "在密钥文件中嵌入备注",
                HelpName = "text"
            };
        }

        public static Command SubCommand()
        {
            var cmd = new Command("genkey",
                """
                生成独立的 .cvk 密钥文件（不打包数据）。

                预先生成密钥，供后续 pack --key-file 使用。

                示例：
                  crypvol genkey
                    生成 ./key.cvk (PlainKey)
                  crypvol genkey -m Password -p "mypassword" -n secret
                    生成 ./secret.cvk (Password)
                  crypvol genkey -o /keys -n project -m Asymmetric --public-key alice.pem
                    生成 /keys/project.cvk (Asymmetric)
                """)
            {
                Output,
                Name,
                Mode,
                Password,
                PublicKey,
                Comment
            };
            cmd.SetAction(GenKeyHelper.Invoker);
            return cmd;
        }
    }
}
