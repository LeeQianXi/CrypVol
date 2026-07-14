using Avalonia.Controls.Notifications;
using CrypVol.Lib.RefPool;

namespace CrypVol.Core.Abstract.Controls;

public class ReferenceNotification : Notification, IReference<ReferenceNotification>
{
    public void Reset()
    {
        Title = null;
        Message = null;
        Type = NotificationType.Information;
        Expiration = TimeSpan.FromSeconds(5.0);
        OnClick = null;
        OnClose = null;
    }

    public void Init(string? title,
        string? message,
        NotificationType type = NotificationType.Information,
        TimeSpan? expiration = null,
        Action? onClick = null,
        Action? onClose = null)
    {
        Title = title;
        Message = message;
        Type = type;
        Expiration = expiration ?? TimeSpan.FromSeconds(5.0);
        OnClick = onClick;
        OnClose = onClose;
    }
}