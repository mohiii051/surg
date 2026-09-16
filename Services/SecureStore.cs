using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SurgeApp.Services;

public sealed class SecureStore
{
    private readonly string _root;

    public SecureStore()
    {
        _root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Surge", "Security");
        Directory.CreateDirectory(_root);
    }

    public void Save(string name, string value)
    {
        var data = Encoding.UTF8.GetBytes(value);
        var protectedData = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
        File.WriteAllBytes(GetPath(name), protectedData);
    }

    public string? Load(string name)
    {
        var path = GetPath(name);
        if (!File.Exists(path)) return null;
        try
        {
            var encrypted = File.ReadAllBytes(path);
            var data = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(data);
        }
        catch { return null; }
    }

    public void Delete(string name)
    {
        try
        {
            var path = GetPath(name);
            if (File.Exists(path)) File.Delete(path);
        }
        catch { }
    }

    private string GetPath(string name)
    {
        foreach (var c in name)
            if (!(char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.'))
                throw new ArgumentException("Invalid secure store key.", nameof(name));
        return Path.Combine(_root, name + ".bin");
    }
}
