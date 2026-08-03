using System.CommandLine;
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

namespace CrypVol.Cli;

/// <summary>
///     CrypVol CLI 完整的命令树定义
/// </summary>
public static class CommandDefinition
{
    // ═══════════════════════════════════════════════════════════════
    //  全局选项
    // ═══════════════════════════════════════════════════════════════

    /// <summary>启用详细日志输出（全局可用）</summary>
    public static readonly Option<bool> Verbose = new("--verbose", "-v")
    {
        Description = "输出详细的处理日志（全局可用）",
        Recursive = true
    };

    // ═══════════════════════════════════════════════════════════════
    //  根命令
    // ═══════════════════════════════════════════════════════════════

    public static RootCommand BuildCommand()
    {
        var root = new RootCommand(
            """
            CrypVol —— 加密分卷归档工具 (Cryptographic Volume Package)

            将文件或目录打包为带加密保护的 .cvp 数据卷，支持分卷存储、压缩、
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
            Convert.SubCommand(),
            new DiagramDirective()
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
        public static readonly Option<FileInfo> KeyFile;
        public static readonly Option<EncryptionMode> Mode;
        public static readonly Option<string> Password;
        public static readonly Option<IEnumerable<FileInfo>> PublicKey;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;
        public static readonly Option<bool> Compress;
        public static readonly Option<int> CompressionLevel;
        public static readonly Option<int> Threads;
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
                Description = "单个数据卷的大小上限（单位：MiB）。超出该大小的数据将自动切分为多个卷",
                HelpName = "mib",
                DefaultValueFactory = static _ => 1024u
            };

            // ── 加密选项：两种模式互斥 ──
            //   A) 指定 --key-file → 复用已有 .cvk 的 CEK（--mode/--password/--public-key 忽略）
            //   B) 不指定       → 生成新 CEK + 新 .cvk（--mode 等必需）

            KeyFile = new Option<FileInfo>("--key-file", "-k")
            {
                Description =
                    """
                    指定已有 .cvk 密钥文件，直接使用其 CEK 加密数据。
                    提供此选项时，--mode / --password / --public-key 均被忽略。
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
                    RSA/ECC 公钥文件（PEM 格式）。仅在未指定 --key-file 且 --mode Asymmetric 时生效。
                    可多次指定以支持多个接收者。
                    KeyID 默认为文件名（不含扩展名），用于标识密钥。
                    """,
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            // ── 压缩选项 ──
            Compress = new Option<bool>("--compress", "-c")
            {
                Description = "启用 GZip 数据压缩，减小卷文件体积（会略微增加 CPU 开销）"
            };

            CompressionLevel = new Option<int>("--compression-level")
            {
                Description =
                    """
                    GZip 压缩级别：0 = 仅存储不压缩，9 = 最高压缩比。
                    仅在启用 --compress 时生效。
                    """,
                HelpName = "0-9",
                DefaultValueFactory = static _ => 6
            }.AcceptOnlyFromAmong("0", "1", "2", "3", "4", "5", "6", "7", "8", "9");

            // ── 处理选项 ──
            Threads = new Option<int>("--threads", "-t")
            {
                Description =
                    """
                    并行处理线程数。影响压缩和加密阶段的并发度。
                    设为 1 禁用并行；设为 0 表示自动（使用全部 CPU 核心）。
                    """,
                HelpName = "count",
                DefaultValueFactory = static _ => Environment.ProcessorCount
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
                Description = "仅打包匹配 Glob 模式的文件。可多次指定以添加多个模式",
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
                    嵌入数据完整性校验信息：

                    None   —— 不嵌入校验数据（体积最小，但无法检测数据损坏）
                    Block  —— 每个 4KB 数据块附带 CRC32（默认）
                    File   —— 块级校验 + 每个文件附带 SHA256
                    Volume —— 上述全部 + 卷末尾附带整卷 SHA256（最高安全性）
                    """,
                DefaultValueFactory = static _ => IntegrityLevel.File
            };

            // ── 预览 ──
            DryRun = new Option<bool>("--dry-run")
            {
                Description =
                    """
                    预估模式：不实际写入任何数据，仅计算并输出：
                      - 预计生成的卷文件数量及大小
                      - 每个卷的文件列表
                      - .cvk 密钥文件的加密模式
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

                打包流程：扫描源路径 → 应用 Glob 过滤 → 预分配数据到各卷
                → 并行读取原始数据 → 压缩/加密处理 → 按卷写入磁盘。

                示例：
                  crypvol pack ./docs -m Password -p "secret123" -c
                  crypvol pack ./photos -s 2048 --include "**/*.jpg"
                  crypvol pack ./data -m Asymmetric --public-key alice.pem --public-key bob.pem
                  crypvol pack ./archive --dry-run
                """)
            {
                InputPath,
                OutputPath,
                OutputPrefix,
                VolumeSize,
                KeyFile,
                Mode,
                Password,
                PublicKey,
                PrivkeyKey,
                PrivkeyKeyPass,
                Compress,
                CompressionLevel,
                Threads,
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
        public static readonly Option<int> Threads;
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
                Description = "RSA/ECC 私钥文件路径（Asymmetric 模式必需）",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件本身的解密密码（仅私钥文件本身受密码保护时需要）",
                HelpName = "passphrase"
            };

            Threads = new Option<int>("--threads", "-t")
            {
                Description = "并行解压/解密线程数。0 表示自动",
                HelpName = "count",
                DefaultValueFactory = static _ => Environment.ProcessorCount
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
                从加密卷 (.cvp) 中还原文件。

                自动发现同组的所有卷文件，无需逐个指定。
                支持按文件名 Glob 过滤、覆盖控制、Unix 权限还原。

                示例：
                  crypvol extract ./archive.1.cvp
                    自动发现同目录下 archive.2.cvp, archive.3.cvp...，一并还原

                  crypvol extract ./data.1.cvp -p "secret123" -o ./restored --overwrite
                    用密码解密 .cvk，提取到 ./restored，覆盖已存在文件

                  crypvol extract ./vol.1.cvp --privkey-key ./mykey.pem --include "**/*.docx"
                    用 RSA 私钥解密，仅提取 Word 文档

                  crypvol extract ./vol.1.cvp --dry-run
                    预览将还原的文件，不实际写入
                """)
            {
                VolFiles,
                Output,
                KeyFile,
                Password,
                PrivkeyKey,
                PrivkeyKeyPass,
                Threads,
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
                Description = "长格式输出：显示文件大小、修改时间、文件权限、卷号等详细信息"
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
                Description = "RSA/ECC 私钥文件路径",
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
        }

        public static Command SubCommand()
        {
            var cmd = new Command("browse",
                """
                列出加密卷 (.cvp) 中的文件清单，无需完整解包。

                即使卷内容已加密，也可以浏览文件名和目录结构（PlainKey 模式下无需密钥）。
                支持多种输出格式和排序方式。

                示例：
                  crypvol browse ./archive.1.cvp
                    以表格形式列出所有文件

                  crypvol browse ./archive.1.cvp --long --sort Size --reverse
                    按文件大小从大到小列出（长格式）

                  crypvol browse ./archive.1.cvp -o filelist.csv -f Csv
                    导出为 CSV 文件

                  crypvol browse ./archive.1.cvp --show-fragments --include "**/bigfile.*"
                    查看大文件跨卷分段的详情
                """)
            {
                VolFiles,
                LongFormat,
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
                Description = "密钥文件解密密码。提供后将尝试验证密码并显示 CEK 指纹等额外信息",
                HelpName = "passphrase"
            };

            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = "RSA/ECC 私钥文件路径。提供后将尝试验证并显示额外信息",
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
                显示密钥文件 (.cvk) 的元数据信息。

                输出内容包括：文件格式版本、密钥保护模式、Argon2id 参数（Password模式）、
                接收者列表及 KeyID（Asymmetric 模式）、CEK 指纹（需提供解密凭据）等。

                示例：
                  crypvol info ./archive.cvk
                    查看 .cvk 的基本元数据（模式、版本等）

                  crypvol info ./archive.cvk -f Json
                    以 JSON 格式输出元数据

                  crypvol info ./archive.cvk -p "secret123"
                    验证密码并展示 CEK 指纹等完整信息
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
        public static readonly Option<int> Threads;
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
                Description = "RSA/ECC 私钥文件路径",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件本身的密码",
                HelpName = "passphrase"
            };

            Threads = new Option<int>("--threads", "-t")
            {
                Description = "并行校验线程数。0 表示自动",
                HelpName = "count",
                DefaultValueFactory = static _ => Environment.ProcessorCount
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

                逐块验证 CRC32 / SHA256 校验值（取决于打包时的 --integrity 设置），
                报告任何数据损坏或不一致。可生成损坏报告供 repair 命令使用。

                退出码：0 = 完整无损坏，1 = 检测到损坏，2 = 无法读取/致命错误

                示例：
                  crypvol verify ./archive.1.cvp
                    校验所有卷，报告损坏情况

                  crypvol verify ./archive.1.cvp --quick
                    快速检查卷头结构完整性

                  crypvol verify ./archive.1.cvp -r damage-report.txt
                    校验并生成详细损坏报告
                """)
            {
                VolFiles,
                KeyFile,
                Password,
                PrivkeyKey,
                PrivkeyKeyPass,
                Threads,
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
        public static readonly Option<int> Threads;
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
                Description = "RSA/ECC 私钥文件路径",
                HelpName = "pem-file"
            }.AcceptExistingOnly();

            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件本身的密码",
                HelpName = "passphrase"
            };

            Threads = new Option<int>("--threads", "-t")
            {
                Description = "并行处理线程数",
                HelpName = "count",
                DefaultValueFactory = static _ => Environment.ProcessorCount
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
                尝试修复损坏的 .cvp 数据卷。

                通过冗余校验信息（CRC32 / SHA256）定位损坏区域，并尝试
                尽可能恢复数据。无法恢复的损坏区域将被标记或零填充。

                修复原理：
                  1. 扫描卷结构，定位可识别的文件和段头
                  2. 逐块校验数据完整性
                  3. 无法恢复的块标记为损坏（后续 extract --rescue 会跳过）

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
                Threads,
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

        public static readonly Option<int> Threads;
        public static readonly Option<bool> Backup;


        static Convert()
        {
            VolFiles = new Argument<ICollection<FileSystemInfo>>("cvp")
            {
                Description =
                    """
                    一个或多个 .cvp 数据卷文件。
                    只需提供需要转换的卷（不必是全部卷），程序自动发现同组文件。
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
                Description = "新卷文件的文件名前缀。未指定时沿用原前缀",
                HelpName = "name"
            };

            // 目标密钥：两种模式互斥
            //   A) 指定 --key-file → 复用已有 .cvk 的 CEK（--mode/--password/--public-key 忽略）
            //   B) 不指定       → 生成新 CEK + 新 .cvk（--mode 等必需）

            KeyFile = new Option<FileInfo>("--key-file")
            {
                Description =
                    """
                    指定目标 .cvk 密钥文件，直接使用其 CEK 作为新加密密钥。
                    提供此选项时，--mode / --password / --public-key 均被忽略。
                    """,
                HelpName = "cvk-file"
            }.AcceptExistingOnly();
            Password = new Option<string>("--password", "-p")
            {
                Description = "新密钥的加密密码（Password 模式）",
                HelpName = "passphrase"
            };

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

            Threads = new Option<int>("--threads", "-t")
            {
                Description = "并行处理线程数",
                HelpName = "count",
                DefaultValueFactory = static _ => Environment.ProcessorCount
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
                块级密钥轮换：用旧 CEK 解密每个数据块，用新 CEK 重新加密。

                不解压、不还原文件，仅替换加密层。每个卷独立转换，
                可只转换部分卷，无需所有卷在场。

                目标密钥来源二选一：
                  --key-file <cvk>  复用已有 .cvk 的 CEK
                  --mode/--password  生成新 CEK + 新 .cvk

                典型场景：密钥轮换、为不同节点分发不同密钥域的数据。

                示例：
                  crypvol convert ./archive.1.cvp -k ./old.cvk -o ./new
                    转换指定卷，使用新的 CEK

                  crypvol convert ./archive.1.cvp -k ./old.cvk -m Password -p "newpass" -o ./new
                    转换并用密码保护新 CEK
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
                Threads,
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
                Description = "RSA/ECC 公钥 PEM 文件（Asymmetric 模式必需）",
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