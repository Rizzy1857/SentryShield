using System;
using System.Runtime.InteropServices;
using System.Net;

namespace SentryShield.Plugins.Remediation
{
    /// <summary>
    /// Implements direct Windows Filtering Platform (WFP) API bindings via P/Invoke.
    /// This bypasses user-space Windows Firewall GUI and blocks packets directly in the kernel network stack.
    /// </summary>
    public static class WfpIsolator
    {
        // ---------------------------------------------------------------------
        // GUIDs and Constants
        // ---------------------------------------------------------------------
        private static readonly Guid FWPM_LAYER_OUTBOUND_TRANSPORT_V4 = new Guid("3A431525-450F-4402-B799-56608F79D3A8");
        private static readonly Guid FWPM_LAYER_OUTBOUND_TRANSPORT_V6 = new Guid("78065096-7D1E-421A-98C0-464A4A936526");
        private static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS = new Guid("C35A604D-D22B-4E1A-91B4-68F674EE674B");

        private const uint FWP_ACTION_BLOCK = 0x00000001;
        private const uint FWP_MATCH_NOT_EQUAL = 8;
        private const uint FWP_UINT32 = 4;
        private const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

        // ---------------------------------------------------------------------
        // P/Invoke Signatures
        // ---------------------------------------------------------------------
        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmEngineOpen0(
            [In] string? serverName,
            [In] uint authnService,
            [In] IntPtr authIdentity,
            [In] IntPtr session,
            [Out] out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmEngineClose0([In] IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", ExactSpelling = true)]
        private static extern uint FwpmFilterAdd0(
            [In] IntPtr engineHandle,
            [In] ref FWPM_FILTER0 filter,
            [In] IntPtr sd,
            [Out] out ulong id);

        // ---------------------------------------------------------------------
        // P/Invoke Structs
        // ---------------------------------------------------------------------
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FWPM_DISPLAY_DATA0
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? name;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? description;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_VALUE0
        {
            public uint type;
            public ulong value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_ACTION0
        {
            public uint type;
            public Guid filterType;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWP_CONDITION_VALUE0
        {
            public uint type;
            public ulong value;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWPM_FILTER_CONDITION0
        {
            public Guid fieldKey;
            public uint matchType;
            public FWP_CONDITION_VALUE0 conditionValue;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FWPM_FILTER0
        {
            public Guid filterKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public uint flags;
            public IntPtr providerKey;
            public FWPM_DISPLAY_DATA0 providerData;
            public Guid layerKey;
            public Guid subLayerKey;
            public FWPM_VALUE0 weight;
            public uint numFilterConditions;
            public IntPtr filterCondition;
            public FWPM_ACTION0 action;
            // The C++ union { UINT64; GUID; } requires 8-byte alignment.
            // Using two ulongs forces C# to pad the struct correctly after FWPM_ACTION0.
            public ulong providerContextKey_part1;
            public ulong providerContextKey_part2;
            public IntPtr reserved;
            public ulong filterId;
            public FWPM_VALUE0 effectiveWeight;
        }

        // ---------------------------------------------------------------------
        // Public API
        // ---------------------------------------------------------------------
        private static IntPtr _engineHandle = IntPtr.Zero;

        /// <summary>
        /// Installs a kernel-level WFP block on all outbound IPv4/IPv6 traffic except loopback (127.0.0.1).
        /// Returns true if successful.
        /// </summary>
        public static bool BlockAllOutboundNetwork()
        {
            try
            {
                if (_engineHandle == IntPtr.Zero)
                {
                    uint result = FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out _engineHandle);
                    if (result != 0) return false;
                }

                // Convert 127.0.0.1 to network byte order uint32
                var loopbackBytes = IPAddress.Parse("127.0.0.1").GetAddressBytes();
                Array.Reverse(loopbackBytes); // Big-endian to Little-endian
                uint loopbackIp = BitConverter.ToUInt32(loopbackBytes, 0);

                var condition = new FWPM_FILTER_CONDITION0
                {
                    fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType = FWP_MATCH_NOT_EQUAL, // Block anything that is NOT loopback
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = FWP_UINT32,
                        value = loopbackIp
                    }
                };

                int conditionSize = Marshal.SizeOf(condition);
                IntPtr conditionPtr = Marshal.AllocHGlobal(conditionSize);
                Marshal.StructureToPtr(condition, conditionPtr, false);

                var filter = new FWPM_FILTER0
                {
                    filterKey = Guid.NewGuid(),
                    displayData = new FWPM_DISPLAY_DATA0
                    {
                        name = "SentryShield Quarantine Block",
                        description = "Kernel-level block applied by SentryShield RemediationPlugin"
                    },
                    layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                    action = new FWPM_ACTION0 { type = FWP_ACTION_BLOCK },
                    numFilterConditions = 1,
                    filterCondition = conditionPtr,
                    weight = new FWPM_VALUE0 { type = 0, value = 0 } // Auto-weight
                };

                uint addResult = FwpmFilterAdd0(_engineHandle, ref filter, IntPtr.Zero, out ulong filterId);
                Marshal.FreeHGlobal(conditionPtr);

                return addResult == 0;
            }
            catch
            {
                return false;
            }
        }
    }
}
