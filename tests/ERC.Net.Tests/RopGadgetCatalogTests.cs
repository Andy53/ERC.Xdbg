using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using ERC.Utilities;
using Shouldly;
using Xunit;

namespace ERC.Net.Tests
{
    /// <summary>
    /// Holds the gadget catalogue to the lists the generators actually declare.
    /// </summary>
    /// <remarks>
    /// Every gadget list used to be named by hand in four places per architecture:
    /// once to collect it, once to filter it for usability, once to apply the user's
    /// bad characters, and once to print it. A list missing from one of those copies
    /// failed silently, and two were.
    ///
    /// The catalogue is now the single list of lists. These tests check it against the
    /// fields by reflection, so a list added to one and not the other is a failure
    /// rather than a silent gap.
    /// </remarks>
    public class RopGadgetCatalogTests
    {
        private static IReadOnlyList<string> DeclaredFields(Type listsType)
        {
            return listsType
                .GetFields(BindingFlags.Public | BindingFlags.Instance)
                .Where(f => f.FieldType == typeof(Dictionary<IntPtr, string>))
                .Select(f => f.Name)
                .ToList();
        }

        [Fact]
        public void The_catalogue_covers_every_declared_32_bit_list()
        {
            GadgetCatalog.X86Lists.Select(l => l.Name)
                .ShouldBe(DeclaredFields(typeof(RopChainGenerator32.X86Lists)), ignoreOrder: true);
        }

        [Fact]
        public void The_catalogue_covers_every_declared_64_bit_list()
        {
            // jmpRax and callRax were absent from the bad-character filter; xorRsp and
            // xorRbp were declared but never populated by anything. Both kinds of gap
            // fail this test now.
            GadgetCatalog.X64Lists.Select(l => l.Name)
                .ShouldBe(DeclaredFields(typeof(RopChainGenerator64.X64Lists)), ignoreOrder: true);
        }

        [Fact]
        public void No_list_appears_twice()
        {
            GadgetCatalog.X86Lists.Select(l => l.Name).ShouldBeUnique();
            GadgetCatalog.X64Lists.Select(l => l.Name).ShouldBeUnique();
        }

        [Fact]
        public void Every_entry_reads_and_writes_its_own_field()
        {
            // The accessors are hand-written lambdas, so a copy-paste slip could point
            // two entries at the same field. Writing a distinguishable value through
            // each and reading it back catches that.
            var lists = new RopChainGenerator32.X86Lists();

            for (int i = 0; i < GadgetCatalog.X86Lists.Count; i++)
            {
                var marker = new Dictionary<IntPtr, string> { { new IntPtr(i + 1), "marker" } };
                GadgetCatalog.X86Lists[i].Set(lists, marker);
            }

            for (int i = 0; i < GadgetCatalog.X86Lists.Count; i++)
            {
                GadgetCatalog.X86Lists[i].Get(lists).Keys.Single()
                    .ShouldBe(new IntPtr(i + 1), GadgetCatalog.X86Lists[i].Name);
            }
        }

        [Fact]
        public void Every_64_bit_entry_reads_and_writes_its_own_field()
        {
            var lists = new RopChainGenerator64.X64Lists();

            for (int i = 0; i < GadgetCatalog.X64Lists.Count; i++)
            {
                var marker = new Dictionary<IntPtr, string> { { new IntPtr(i + 1), "marker" } };
                GadgetCatalog.X64Lists[i].Set(lists, marker);
            }

            for (int i = 0; i < GadgetCatalog.X64Lists.Count; i++)
            {
                GadgetCatalog.X64Lists[i].Get(lists).Keys.Single()
                    .ShouldBe(new IntPtr(i + 1), GadgetCatalog.X64Lists[i].Name);
            }
        }

        [Fact]
        public void Each_list_names_the_instruction_a_gadget_must_contain()
        {
            // The mnemonic is matched against disassembly text, so it has to be lower
            // case and non-empty or the list silently collects nothing.
            var all = GadgetCatalog.X86Lists.Select(l => new { l.Name, l.Mnemonic })
                .Concat(GadgetCatalog.X64Lists.Select(l => new { l.Name, l.Mnemonic }));

            foreach (var list in all)
            {
                list.Mnemonic.ShouldNotBeNullOrWhiteSpace(list.Name);
                list.Mnemonic.ShouldBe(list.Mnemonic.ToLowerInvariant(), list.Name);
            }
        }

        [Fact]
        public void The_pushad_list_looks_for_the_mnemonic_the_disassembler_emits()
        {
            // Iced renders 0x60 as "pusha"; SharpDisasm, which it replaced, rendered it
            // as "pushad". Searching for "pushad" finds nothing, and PUSHAD is the
            // instruction the whole VirtualAlloc template is built around.
            GadgetCatalog.X86Lists.Single(l => l.Name == "pushad").Mnemonic.ShouldBe("pusha");
        }

        [Fact]
        public void Register_lists_look_for_that_register()
        {
            // "popEdi" must look for "pop edi" and not, say, "pop esi". Derived from the
            // field name rather than restating the table, so this is an independent check.
            foreach (var list in GadgetCatalog.X86Lists)
            {
                if (list.Name == "pushad" || !list.Name.Any(char.IsUpper))
                {
                    continue;
                }

                int split = list.Name.ToList().FindIndex(char.IsUpper);
                string operation = list.Name.Substring(0, split);
                string register = list.Name.Substring(split).ToLowerInvariant();

                list.Mnemonic.ShouldBe(operation + " " + register);
            }
        }

        [Fact]
        public void The_numeric_operand_rule_matches_how_each_gadget_is_used()
        {
            // A gadget selected for a "pop <reg>" has the next stack slot consumed as
            // the value, so an extra numeric operand shifts everything after it. A
            // "jmp esp" is only ever jumped to, so a literal in it is harmless.
            GadgetCatalog.X86Lists.Single(l => l.Name == "popEdi").ExcludeNumericOperands.ShouldBeTrue();
            GadgetCatalog.X86Lists.Single(l => l.Name == "pushad").ExcludeNumericOperands.ShouldBeTrue();
            GadgetCatalog.X86Lists.Single(l => l.Name == "jmpEsp").ExcludeNumericOperands.ShouldBeFalse();
        }
    }
}
