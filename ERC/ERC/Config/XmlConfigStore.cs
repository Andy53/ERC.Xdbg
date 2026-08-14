using System;
using System.IO;
using System.Reflection;
using System.Xml;

namespace ERC.Config
{
    /// <summary>
    /// Reads and writes ERC_Config.XML.
    /// </summary>
    /// <remarks>
    /// The element names and layout are unchanged from previous versions, so an
    /// existing ERC_Config.XML keeps working after the upgrade.
    /// </remarks>
    public class XmlConfigStore : IConfigStore
    {
        private const string DefaultFileName = "ERC_Config.XML";

        private readonly string _path;

        public XmlConfigStore(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ArgumentNullException("path");
            }

            _path = path;
        }

        /// <summary>
        /// Full path of the config file backing this store.
        /// </summary>
        public string Path { get { return _path; } }

        /// <summary>
        /// The directory holding the running assembly, which is where the plugin
        /// keeps its config and output.
        /// </summary>
        /// <remarks>
        /// Uses AppContext.BaseDirectory. The previous code took
        /// Assembly.CodeBase and stripped six characters to remove the "file:/"
        /// prefix, which is fragile and breaks under shadow copying.
        /// </remarks>
        public static string DefaultDirectory()
        {
            string directory = AppContext.BaseDirectory;

            if (string.IsNullOrEmpty(directory))
            {
                directory = System.IO.Path.GetDirectoryName(
                    new Uri(typeof(XmlConfigStore).Assembly.CodeBase).LocalPath);
            }

            if (!directory.EndsWith("\\", StringComparison.Ordinal))
            {
                directory += "\\";
            }

            return directory;
        }

        /// <summary>
        /// The config file path used when none is supplied.
        /// </summary>
        public static string DefaultPath()
        {
            return System.IO.Path.Combine(DefaultDirectory(), DefaultFileName);
        }

        public ErcConfig Load()
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            try
            {
                var document = new XmlDocument();
                document.Load(_path);

                return new ErcConfig
                {
                    WorkingDirectory   = Read(document, "//Working_Directory"),
                    Author             = Read(document, "//Author"),
                    PatternStandardPath = Read(document, "//Standard_Pattern"),
                    PatternExtendedPath = Read(document, "//Extended_Pattern"),
                    SystemErrorLogPath = Read(document, "//Error_Log_File")
                };
            }
            catch (XmlException)
            {
                // Malformed file: treated as absent so defaults are written over it.
                return null;
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
        }

        public bool Save(ErcConfig config)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }

            try
            {
                var document = new XmlDocument();
                XmlDeclaration declaration = document.CreateXmlDeclaration("1.0", "UTF-8", null);
                document.InsertBefore(declaration, document.DocumentElement);

                XmlElement root = document.CreateElement(string.Empty, "ERC.Net",
                    typeof(XmlConfigStore).Assembly.GetName().Version.ToString());
                document.AppendChild(root);

                XmlElement parameters = document.CreateElement(string.Empty, "Parameters", string.Empty);
                root.AppendChild(parameters);

                Write(document, parameters, "Working_Directory", config.WorkingDirectory);
                Write(document, parameters, "Author", config.Author);
                Write(document, parameters, "Standard_Pattern", config.PatternStandardPath);
                Write(document, parameters, "Extended_Pattern", config.PatternExtendedPath);
                Write(document, parameters, "Error_Log_File", config.SystemErrorLogPath);

                document.Save(_path);
                return true;
            }
            catch (IOException)
            {
                // An unwritable plugin directory is a normal deployment, not a fault.
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        private static string Read(XmlDocument document, string xpath)
        {
            XmlNode node = document.DocumentElement == null
                ? null
                : document.DocumentElement.SelectSingleNode(xpath);

            return node == null ? null : node.InnerText;
        }

        private static void Write(XmlDocument document, XmlElement parent, string name, string value)
        {
            XmlElement element = document.CreateElement(string.Empty, name, string.Empty);
            element.AppendChild(document.CreateTextNode(value ?? string.Empty));
            parent.AppendChild(element);
        }
    }
}
