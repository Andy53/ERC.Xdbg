using Managed.x64dbg.SDK;
using Microsoft.VisualBasic;
using Microsoft.VisualBasic.CompilerServices;

namespace ErcXdbg
{
    public static class RegisteredCommands
    {
        public static bool ErcCommand(int argc, string[] argv)
        {
            PLog.WriteLine("[.net TEST] .Net test command!");
            string empty = string.Empty;
            string Left = Interaction.InputBox("Enter value pls", "NetTest", "", -1, -1);
            if (Left == null | Operators.CompareString(Left, "", false) == 0)
                PLog.WriteLine("[TEST] cancel pressed!");
            else
                PLog.WriteLine("[TEST] line: {0}", Left);
            return true;
        }
    }
}
