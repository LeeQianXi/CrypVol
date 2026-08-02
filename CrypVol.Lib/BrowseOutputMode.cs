namespace CrypVol.Lib;

/// <summary>浏览输出格式</summary>
public enum BrowseOutputMode
{
    /// <summary>人类可读的表格</summary>
    Table,

    /// <summary>逗号分隔值</summary>
    Csv,

    /// <summary>JSON 格式</summary>
    Json,

    /// <summary>YAML 格式</summary>
    Yaml
}

/// <summary>浏览列表排序字段</summary>
public enum BrowseSortField
{
    /// <summary>按文件名排序</summary>
    Name,

    /// <summary>按文件大小排序</summary>
    Size,

    /// <summary>按修改时间排序</summary>
    Date
}