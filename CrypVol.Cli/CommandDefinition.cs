using System.CommandLine;
using CrypVol.Cli.Browse;
using CrypVol.Cli.Extract;
using CrypVol.Cli.Info;
using CrypVol.Cli.Pack;
using CrypVol.Lib;

namespace CrypVol.Cli;

public static class CommandDefinition
{
    public static readonly Option<bool> Verbose = new("--verbose", "-v")
    {
        Description = "显示详细日志输出",
        Recursive = true
    };

    public static RootCommand BuildCommand()
    {
        var root = new RootCommand("CrypVol - 加密分卷归档工具 (Cryptographic Volume Package)")
        {
            Verbose,
            Pack.SubCommand(),
            Extract.SubCommand(),
            Browse.SubCommand(),
            Info.SubCommand(),
            new DiagramDirective()
        };
        return root;
    }

    public static class Pack
    {
        public static readonly Argument<FileSystemInfo> InputPath;
        public static readonly Option<DirectoryInfo> OutputPath;
        public static readonly Option<string> OutputPrefix;
        public static readonly Option<uint> VolumeSize;
        public static readonly Option<EncryptionMode> Mode;
        public static readonly Option<string> Password;
        public static readonly Option<IEnumerable<FileInfo>> PublicKey;
        public static readonly Option<int> Threads;
        public static readonly Option<bool> Compress;
        public static readonly Option<DirectoryInfo> KeyOutputPath;
        public static readonly Option<string> Include;
        public static readonly Option<string> Exclude;

        static Pack()
        {
            InputPath = new Argument<FileSystemInfo>("path")
            {
                Description = "要打包的源路径"
            }.AcceptExistingOnly();
            OutputPath = new Option<DirectoryInfo>("--output", "-o")
            {
                Description = "输出文件目录（默认为输入目录）",
                HelpName = "path",
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
            OutputPrefix = new Option<string>("--output-prefix")
            {
                Description = "输出文件前缀（默认为源目录名），生成的卷文件格式为 <前缀>.<卷号>.cvp，密钥文件为 <前缀>.cvk",
                HelpName = "prefix",
                DefaultValueFactory = static result =>
                {
                    var input = result.GetValue(InputPath);
                    return input switch
                    {
                        FileInfo fi => Path.GetFileNameWithoutExtension(fi.Name) is { } name && !name.IsWhiteSpace()
                            ? name
                            : fi.Directory?.Name!,
                        DirectoryInfo di => di.Name,
                        _ => null!
                    };
                }
            };
            VolumeSize = new Option<uint>("--volume-size", "-s")
            {
                Description = "单个卷的大小（单位 MB）",
                HelpName = "size",
                DefaultValueFactory = static _ => 1024
            };
            Mode = new Option<EncryptionMode>("--mode", "-m")
            {
                Description =
                    """
                    加密模式
                    None:数据为明文或仅经 GZip 压缩，不生成 .cvk 文件
                    PlainKey:CEK 明文存储在 .cvk 中，解密仅需文件本身
                    Password:CEK 经 Argon2id + AES-GCM 加密存储在 .cvk，解密需密码
                    Asymmetric:CEK 经 RSA/ECC 公钥加密存储在 .cvk，解密需对应私钥
                    """,
                DefaultValueFactory = static _ => EncryptionMode.PlainKey
            };
            Password = new Option<string>("--password", "-p")
            {
                Description = "用于加密CEK的密码,仅在 Password 模式生效",
                HelpName = "pass"
            };
            PublicKey = new Option<IEnumerable<FileInfo>>("--public-key")
            {
                Description = "用于加密CEK的公钥,仅在 Pubkey 模式生效",
                HelpName = "file"
            }.AcceptExistingOnly();
            Threads = new Option<int>("--threads", "-t")
            {
                Description = "并行压缩/加密线程数（0 表示自动）",
                HelpName = "count",
                DefaultValueFactory = static _ => Environment.ProcessorCount
            };
            Compress = new Option<bool>("--compress", "-c")
            {
                Description = "启用数据压缩（GZip）"
            };
            KeyOutputPath = new Option<DirectoryInfo>("--key-output")
            {
                Description = "单独指定 .cvk 输出路径（默认与 -o 前缀同名）",
                HelpName = "path",
                DefaultValueFactory = static result => result.GetValue(OutputPath)!
            }.AcceptLegalFilePathsOnly();
            Include = new Option<string>("--include")
            {
                Description = "仅包含匹配的文件（Glob语法）",
                HelpName = "pattern"
            };
            Exclude = new Option<string>("--exclude")
            {
                Description = "排除匹配的文件/目录（Glob语法）",
                HelpName = "pattern"
            };
        }

        public static Command SubCommand()
        {
            var cmd = new Command("pack", "将指定目录打包为加密卷 (.cvp) 并生成对应的密钥文件 (.cvk)")
            {
                InputPath,
                OutputPath,
                OutputPrefix,
                VolumeSize,
                Mode,
                Password,
                PublicKey,
                Threads,
                Compress,
                KeyOutputPath,
                Include,
                Exclude
            };
            cmd.SetAction(PackHelper.Invoker);
            return cmd;
        }
    }

    public static class Extract
    {
        public static readonly Argument<ICollection<FileSystemInfo>> VolFiles;
        public static readonly Option<DirectoryInfo> Output;
        public static readonly Option<FileInfo> KeyFile;
        public static readonly Option<string> Password;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;
        public static readonly Option<int> Threads;
        public static readonly Option<bool> Rescue;
        public static readonly Option<bool> Overwrite;
        public static readonly Option<bool> KeepPermissions;
        public static readonly Option<string> Include;
        public static readonly Option<string> Exclude;

        static Extract()
        {
            VolFiles = new Argument<ICollection<FileSystemInfo>>("cvp")
            {
                Description = "数据卷文件路径（任意一个 .cvp 文件，程序自动搜索同目录其他卷，禁止输入非同组cvp）",
                Arity = ArgumentArity.OneOrMore
            }.AcceptExistingOnly();
            Output = new Option<DirectoryInfo>("--output", "-o")
            {
                Description = "目标还原目录（默认为输入卷所在目录）",
                HelpName = "path",
                DefaultValueFactory = static result =>
                {
                    var input = result.GetValue(VolFiles)?.First();
                    return input switch
                    {
                        FileInfo fi => fi.Directory!,
                        DirectoryInfo di => di,
                        _ => null!
                    };
                }
            }.AcceptLegalFilePathsOnly();
            KeyFile = new Option<FileInfo>("--key-file", "-k")
            {
                Description = "对应的 .cvk 密钥文件路径",
                HelpName = "file"
            }.AcceptExistingOnly();
            Password = new Option<string>("--password", "-p")
            {
                Description = ".cvk 受密码保护时使用",
                HelpName = "pass"
            };
            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = ".cvk 受非对称保护时使用，提供私钥文件",
                HelpName = "file"
            }.AcceptExistingOnly();
            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件本身的密码（若私钥加密）",
                HelpName = "pass"
            };
            Threads = new Option<int>("--threads", "-t")
            {
                Description = "并行解压线程数",
                HelpName = "count",
                DefaultValueFactory = static _ => Environment.ProcessorCount
            };
            Rescue = new Option<bool>("--rescue")
            {
                Description = "启用救援模式（忽略对齐错误，尝试从损坏卷中捞取数据）"
            };
            Overwrite = new Option<bool>("--overwrite")
            {
                Description = "覆盖已存在的文件"
            };
            KeepPermissions = new Option<bool>("--keep-permissions")
            {
                Description = "还原原始文件权限（Unix 模式）"
            };
            Include = new Option<string>("--include")
            {
                Description = "仅包含匹配的文件（Glob语法）",
                HelpName = "pattern"
            };
            Exclude = new Option<string>("--exclude")
            {
                Description = "排除匹配的文件/目录（Glob语法）",
                HelpName = "pattern"
            };
        }

        public static Command SubCommand()
        {
            var cmd = new Command("extract", "从加密卷 (.cvp) 中提取文件")
            {
                VolFiles,
                Output,
                KeyFile,
                Password,
                PrivkeyKey,
                PrivkeyKeyPass,
                Threads,
                Rescue,
                Overwrite,
                KeepPermissions,
                Include,
                Exclude
            };
            cmd.SetAction(ExtractHelper.Invoker);
            return cmd;
        }
    }

    public static class Browse
    {
        public static readonly Argument<ICollection<FileSystemInfo>> VolFiles;
        public static readonly Option<DirectoryInfo?> Output;
        public static readonly Option<BrowseOutputMode> OutputFormat;
        public static readonly Option<bool> ShowFragments;
        public static readonly Option<FileInfo> KeyFile;
        public static readonly Option<string> Password;
        public static readonly Option<FileInfo> PrivkeyKey;
        public static readonly Option<string> PrivkeyKeyPass;
        public static readonly Option<bool> Rescue;
        public static readonly Option<string> Include;
        public static readonly Option<string> Exclude;

        static Browse()
        {
            VolFiles = new Argument<ICollection<FileSystemInfo>>("cvp")
            {
                Description = "数据卷文件路径（任意一个 .cvp 文件，程序自动搜索同目录其他卷，禁止输入非同组cvp）",
                Arity = ArgumentArity.OneOrMore
            }.AcceptExistingOnly();
            Output = new Option<DirectoryInfo?>("--output", "-o")
            {
                Description = "将结果写入文件（默认输出到控制台）",
                HelpName = "file",
                DefaultValueFactory = static result =>
                {
                    var input = result.GetValue(VolFiles)?.First();
                    return input switch
                    {
                        FileInfo fi => fi.Directory,
                        DirectoryInfo di => di,
                        _ => null
                    };
                }
            }.AcceptLegalFilePathsOnly();
            OutputFormat = new Option<BrowseOutputMode>("--output-format", "-f")
            {
                Description = "输出格式",
                HelpName = "format"
            };
            ShowFragments = new Option<bool>("--show-fragments")
            {
                Description = "显示每个文件的段详细信息（卷号、偏移、大小）"
            };
            KeyFile = new Option<FileInfo>("--key-file", "-k")
            {
                Description = "对应的 .cvk 密钥文件路径",
                HelpName = "file"
            }.AcceptExistingOnly();
            Password = new Option<string>("--password", "-p")
            {
                Description = ".cvk 受密码保护时使用",
                HelpName = "pass"
            };
            PrivkeyKey = new Option<FileInfo>("--privkey-key")
            {
                Description = ".cvk 受非对称保护时使用，提供私钥文件",
                HelpName = "file"
            }.AcceptExistingOnly();
            PrivkeyKeyPass = new Option<string>("--key-pass")
            {
                Description = "私钥文件本身的密码（若私钥加密）",
                HelpName = "pass"
            };
            Rescue = new Option<bool>("--rescue")
            {
                Description = "启用救援模式（忽略对齐错误，尝试从损坏卷中捞取数据）"
            };
            Include = new Option<string>("--include")
            {
                Description = "仅包含匹配的文件（Glob语法）",
                HelpName = "pattern"
            };
            Exclude = new Option<string>("--exclude")
            {
                Description = "排除匹配的文件/目录（Glob语法）",
                HelpName = "pattern"
            };
        }

        public static Command SubCommand()
        {
            var cmd = new Command("browse", "列出加密卷中的文件清单")
            {
                VolFiles,
                Output,
                OutputFormat,
                ShowFragments,
                KeyFile,
                Password,
                PrivkeyKey,
                PrivkeyKeyPass,
                Rescue,
                Include,
                Exclude
            };
            cmd.SetAction(BrowseHelper.Invoker);
            return cmd;
        }
    }

    public static class Info
    {
        public static readonly Argument<ICollection<FileSystemInfo>> InputFiles;

        static Info()
        {
            InputFiles = new Argument<ICollection<FileSystemInfo>>("cvk")
            {
                Description = "目标文件（.cvk）"
            }.AcceptExistingOnly();
        }

        public static Command SubCommand()
        {
            var cmd = new Command("info", "显示密钥文件（.cvk）的元数据")
            {
                InputFiles
            };
            cmd.SetAction(InfoHelper.Invoker);
            return cmd;
        }
    }
}