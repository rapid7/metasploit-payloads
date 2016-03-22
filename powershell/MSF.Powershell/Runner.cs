using System;
using System.Collections.Generic;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Text;

namespace MSF.Powershell
{
    public class Runner : IDisposable
    {
        // We use a dictionary of runners based on ID, this means that we can maintain
        // separate sessions if we want to.
        private static Dictionary<string, Runner> _runners;
        private InitialSessionState _state;
        private CustomPSHost _host = null;
        private Runspace _runspace = null;
        private string _id;

        static Runner()
        {
            System.Diagnostics.Debug.Write("Static constructor called");
            _runners = new Dictionary<string, Runner>();
        }

        public static string Execute(string id, string ps)
        {
            System.Diagnostics.Debug.Write(string.Format("Executing command on session {0}", id));
            if (!_runners.ContainsKey(id))
            {
                _runners.Add(id, new Runner(id));
            }
            var runner = _runners[id];
            return runner.Execute(ps);
        }

        public static Runner Get(string id)
        {
            if (!_runners.ContainsKey(id))
            {
                _runners.Add(id, new Runner(id));
            }
            return _runners[id];
        }

        public static void Remove(string id)
        {
            if (_runners.ContainsKey(id))
            {
                _runners[id].Dispose();
                _runners.Remove(id);
            }
        }

        public Runner(string id)
        {
            _id = id;
            _state = InitialSessionState.CreateDefault();
            _state.AuthorizationManager = null;

            _host = new CustomPSHost();

            _runspace = RunspaceFactory.CreateRunspace(_host, _state);
            _runspace.Open();
        }

        public string Execute(string ps)
        {
            using (Pipeline pipeline = _runspace.CreatePipeline())
            {
                pipeline.Commands.AddScript(ps);
                pipeline.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                pipeline.Commands.Add("out-default");
                pipeline.Invoke();
            }

            return _host.GetAndFlushOutput();
        }

        public void Dispose()
        {
            if (_runspace != null)
            {
                _runspace.Close();
                _runspace.Dispose();
            }
        }

        private class CustomPSHost : PSHost
        {
            private Guid _hostId;
            private CustomPSHostUserInterface _ui = null;

            public CustomPSHost()
            {
                _hostId = Guid.NewGuid();
                _ui = new CustomPSHostUserInterface();
            }

            public string GetAndFlushOutput()
            {
                var output = _ui.ToString();
                _ui.Clear();
                return output;
            }

            public override System.Globalization.CultureInfo CurrentCulture
            {
                get { return System.Threading.Thread.CurrentThread.CurrentCulture; }
            }

            public override System.Globalization.CultureInfo CurrentUICulture
            {
                get { return System.Threading.Thread.CurrentThread.CurrentUICulture; }
            }

            public override void EnterNestedPrompt()
            {
            }

            public override void ExitNestedPrompt()
            {
            }

            public override Guid InstanceId
            {
                get { return _hostId; }
            }

            public override string Name
            {
                get { return "MSFConsole"; }
            }

            public override void NotifyBeginApplication()
            {
            }

            public override void NotifyEndApplication()
            {
            }

            public override void SetShouldExit(int exitCode)
            {
            }

            public override PSHostUserInterface UI
            {
                get { return _ui; }
            }

            public override Version Version
            {
                get { return new Version(0, 1); }
            }
        }

        private class CustomPSHostUserInterface : PSHostUserInterface
        {
            private StringBuilder _buffer;
            private CustomPSHostRawUserInterface _rawUI;

            public CustomPSHostUserInterface()
            {
                _buffer = new StringBuilder();
                _rawUI = new CustomPSHostRawUserInterface();
            }

            public override string ToString()
            {
                return _buffer.ToString();
            }

            public void Clear()
            {
                _buffer.Remove(0, _buffer.Length);
            }

            public override Dictionary<string, System.Management.Automation.PSObject> Prompt(string caption, string message, System.Collections.ObjectModel.Collection<FieldDescription> descriptions)
            {
                return new Dictionary<string, System.Management.Automation.PSObject>();
            }

            public override int PromptForChoice(string caption, string message, System.Collections.ObjectModel.Collection<ChoiceDescription> choices, int defaultChoice)
            {
                return 0;
            }

            public override System.Management.Automation.PSCredential PromptForCredential(string caption, string message, string userName, string targetName, System.Management.Automation.PSCredentialTypes allowedCredentialTypes, System.Management.Automation.PSCredentialUIOptions options)
            {
                return null;
            }

            public override System.Management.Automation.PSCredential PromptForCredential(string caption, string message, string userName, string targetName)
            {
                return null;
            }

            public override PSHostRawUserInterface RawUI
            {
                get { return _rawUI; }
            }

            public override string ReadLine()
            {
                return string.Empty;
            }

            public override System.Security.SecureString ReadLineAsSecureString()
            {
                return new System.Security.SecureString();
            }

            public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
            {
                _buffer.Append(value);
            }

            public override void Write(string value)
            {
                _buffer.Append(value);
            }

            public override void WriteDebugLine(string message)
            {
                _buffer.Append("DEBUG: ");
                _buffer.AppendLine(message);
            }

            public override void WriteErrorLine(string value)
            {
                _buffer.Append("ERROR: ");
                _buffer.AppendLine(value);
            }

            public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
            {
                _buffer.AppendLine(value);
            }

            public override void WriteLine(string value)
            {
                _buffer.AppendLine(value);
            }

            public override void WriteLine()
            {
                _buffer.AppendLine();
            }

            public override void WriteProgress(long sourceId, System.Management.Automation.ProgressRecord record)
            {
            }

            public override void WriteVerboseLine(string message)
            {
                _buffer.Append("VERBOSE: ");
                _buffer.AppendLine(message);
            }

            public override void WriteWarningLine(string message)
            {
                _buffer.Append("WARNING: ");
                _buffer.AppendLine(message);
            }
        }

        private class CustomPSHostRawUserInterface : PSHostRawUserInterface
        {

            public override ConsoleColor BackgroundColor
            {
                get { return ConsoleColor.Black; }
                set { }
            }

            public override Size BufferSize
            {
                get { return new Size(120, 100); }
                set { }
            }

            public override Coordinates CursorPosition
            {
                get { return new Coordinates(0, 0); }
                set { }
            }

            public override int CursorSize
            {
                get { return 1; }
                set { }
            }

            public override void FlushInputBuffer()
            {
            }

            public override ConsoleColor ForegroundColor
            {
                get { return ConsoleColor.White; }
                set { }
            }

            public override BufferCell[,] GetBufferContents(Rectangle rectangle)
            {
                return new BufferCell[0,0];
            }

            public override bool KeyAvailable
            {
                get { return false; }
            }

            public override Size MaxPhysicalWindowSize
            {
                get { return new Size(int.MaxValue, int.MaxValue); }
            }

            public override Size MaxWindowSize
            {
                get { return new Size(120, 100); }
            }

            public override KeyInfo ReadKey(ReadKeyOptions options)
            {
                return new KeyInfo();
            }

            public override void ScrollBufferContents(Rectangle source, Coordinates destination, Rectangle clip, BufferCell fill)
            {
            }

            public override void SetBufferContents(Rectangle rectangle, BufferCell fill)
            {
            }

            public override void SetBufferContents(Coordinates origin, BufferCell[,] contents)
            {
            }

            public override Coordinates WindowPosition
            {
                get { return new Coordinates(-200, -200); }
                set { }
            }

            public override Size WindowSize
            {
                get { return new Size(120, 100); }
                set { }
            }

            public override string WindowTitle
            {
                get { return string.Empty; }
                set { }
            }
        }
    }
}
