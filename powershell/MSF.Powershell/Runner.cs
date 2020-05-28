using System;
using System.Collections.Generic;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

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
            System.Diagnostics.Debug.Write("[PSH RUNNER] Static constructor called");
            _runners = new Dictionary<string, Runner>();
        }

        internal static void Channelise(string id, Int64 channelWriter, Int64 context)
        {
            var runner = Get(id);
            System.Diagnostics.Debug.Write(string.Format("[PSH RUNNER] Channelising {0} with CW 0x{1:X} - CTX 0x{2:X}", id, channelWriter, context));
            runner._host.UserInterface.Channelise(channelWriter, context);
        }

        internal static void Unchannelise(string id)
        {
            var runner = Get(id);
            System.Diagnostics.Debug.Write(string.Format("[PSH RUNNER] Unchannelising {0}", id));
            runner._host.UserInterface.Unchannelise();
        }

        internal static string Execute(string id, string ps)
        {
            System.Diagnostics.Debug.Write(string.Format("[PSH RUNNER] Executing command on session {0}", id));
            if (!_runners.ContainsKey(id))
            {
                _runners.Add(id, new Runner(id));
            }
            var runner = _runners[id];
            return runner.Execute(ps);
        }

        internal static Runner Get(string id)
        {
            if (!_runners.ContainsKey(id))
            {
                _runners.Add(id, new Runner(id));
            }
            return _runners[id];
        }

        internal static void Remove(string id)
        {
            if (_runners.ContainsKey(id))
            {
                _runners[id].Dispose();
                _runners.Remove(id);
            }
        }

        internal Runner(string id)
        {
            _id = id;
            _state = InitialSessionState.CreateDefault();
            _state.AuthorizationManager = null;

            _host = new CustomPSHost();

            _runspace = RunspaceFactory.CreateRunspace(_host, _state);
            _runspace.Open();

            // add support straight up for the existing scripts
            foreach(var script in Scripts.GetAllScripts())
            {
                Execute(script);
            }
        }

        private string InvokePipline(string ps)
        {
            ps = "IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes(ps), Base64FormattingOptions.None) + "\")))";
            System.Diagnostics.Debug.Write(string.Format("[PSH RUNNER] Executing PS directly: {0}", ps));
            using (Pipeline pipeline = _runspace.CreatePipeline())
            {
                pipeline.Commands.AddScript(ps);
                pipeline.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                pipeline.Commands.Add("out-default");

                pipeline.Invoke();
            }

            return _host.GetAndFlushOutput();
        }

        private void ThreadInvokePipeline(object psObj)
        {
            // Sneak a prompt string in at the end.
            var ps = psObj.ToString();
            ps = "IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes(ps), Base64FormattingOptions.None) + "\")))";
            System.Diagnostics.Debug.Write(string.Format("[PSH RUNNER] Executing PS on thread: {0}", ps));
            using (Pipeline pipeline = _runspace.CreatePipeline())
            {
                pipeline.Commands.AddScript(ps);
                pipeline.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                pipeline.Commands.Add("out-default");

                pipeline.Invoke();
                System.Diagnostics.Debug.Write(string.Format("[PSH RUNNER] Executed PS on thread. Flushing"));
                _host.GetAndFlushOutput();
                _host.UserInterface.WriteRaw("PS > ");
            }
        }

        internal string Execute(string ps)
        {
            if (_host.UserInterface.IsChannelised)
            {
                var t = new Thread(new ParameterizedThreadStart(ThreadInvokePipeline));
                t.Start(ps);
                return string.Empty;
            }

            return InvokePipline(ps);
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

            public CustomPSHostUserInterface UserInterface
            {
                get { return _ui; }
            }

            public CustomPSHost()
            {
                _hostId = Guid.NewGuid();
                _ui = new CustomPSHostUserInterface();
            }

            public string GetAndFlushOutput()
            {
                var output = _ui.ToString();
                _ui.Clear();
                System.Diagnostics.Debug.Write(string.Format("Output: {0}", output));
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

            private delegate void WriteChannel(Int64 context, byte[] buffer);
            private WriteChannel _chanWriter = null;
            private Int64 _context = 0;

            public CustomPSHostUserInterface()
            {
                _buffer = new StringBuilder();
                _rawUI = new CustomPSHostRawUserInterface();
            }

            public bool IsChannelised
            {
                get { return _chanWriter != null; }
            }

            public override string ToString()
            {
                return _buffer.ToString();
            }

            public void Channelise(Int64 channelWriter, Int64 context)
            {
                _chanWriter = (WriteChannel)Marshal.GetDelegateForFunctionPointer(new IntPtr(channelWriter), typeof(WriteChannel));
                _context = context;
            }

            public void Unchannelise()
            {
                _chanWriter = null;
                _context = 0;
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

            public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string message)
            {
                WriteTarget(message.TrimEnd());
            }

            public override void Write(string message)
            {
                WriteTarget(message.TrimEnd());
            }

            public void WriteRaw(string message)
            {
                WriteTarget(message);
            }

            public override void WriteDebugLine(string message)
            {
                WriteTarget(string.Format("DEBUG: {0}\n", message.TrimEnd()));
            }

            public override void WriteErrorLine(string message)
            {
                WriteTarget(string.Format("ERROR: {0}\n", message.TrimEnd()));
            }

            public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string message)
            {
                WriteTarget(string.Format("{0}\n", message.TrimEnd()));
            }

            public override void WriteLine(string message)
            {
                WriteTarget(string.Format("{0}\n", message.TrimEnd()));
            }

            public override void WriteLine()
            {
                WriteTarget("\n");
            }

            public override void WriteProgress(long sourceId, System.Management.Automation.ProgressRecord record)
            {
            }

            public override void WriteVerboseLine(string message)
            {
                WriteTarget(string.Format("VERBOSE: {0}\n", message.TrimEnd()));
            }

            public override void WriteWarningLine(string message)
            {
                WriteTarget(string.Format("WARNING: {0}\n", message.TrimEnd()));
            }

            private void WriteTarget(string message)
            {
                if (IsChannelised)
                {
                    var bytes = System.Text.Encoding.ASCII.GetBytes(message);
                    System.Diagnostics.Debug.WriteLine(string.Format("[PSH BINDING] Writing to channel {0:X} -{1}", _context, message));
                    _chanWriter(_context, bytes);
                }
                else
                {
                    //System.Diagnostics.Debug.WriteLine("[PSH BINDING] Writing to buffer: " + message);
                    _buffer.Append(message);
                }
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
