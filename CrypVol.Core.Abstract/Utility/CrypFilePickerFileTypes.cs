using Avalonia.Platform.Storage;

namespace CrypVol.Core.Abstract.Utility;

public static class CrypFilePickerFileTypes
{
    public static readonly FilePickerFileType CrypVolFile = new("Cryp加密卷(.cvp)")
    {
        Patterns = ["*.cvp"],
        MimeTypes = ["cvp/*"]
    };
}