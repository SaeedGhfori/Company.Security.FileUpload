namespace Company.Security.FileUpload.Core.Enums;

[Flags]
public enum FileTypeCategory
{
    None = 0,
    Image = 1,
    Video = 2,
    Audio = 4,
    Document = 8,
    Office = 16,
    Archive = 32,
    Binary = 64,
    Text = 128,
    Svg = 256,
    Unknown = 1024,
    All = Image | Video | Audio | Document | Office | Archive | Binary | Text | Svg
}
