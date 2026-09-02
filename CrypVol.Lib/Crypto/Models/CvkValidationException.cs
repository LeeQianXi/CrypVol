namespace CrypVol.Lib.Crypto.Models;

/// <summary>表示 CVK 构建参数不符合所选封装模式的错误。</summary>
public sealed class CvkValidationException : InvalidOperationException
{
    /// <summary>使用指定错误信息创建异常。</summary>
    /// <param name="message">可直接展示给用户的参数错误说明。</param>
    public CvkValidationException(string message)
        : base(message)
    {
    }
}