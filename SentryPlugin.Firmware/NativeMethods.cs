using System;
using System.Runtime.InteropServices;

namespace SentryShield.Plugin.Firmware
{
    internal static class NativeMethods
    {
        /// <summary>
        /// Enumerates all system firmware tables of the specified type.
        /// </summary>
        /// <param name="FirmwareTableProviderSignature">
        /// The identifier of the firmware table provider to direct the query to.
        /// For RSMB (Raw SMBIOS), this is 0x424D5352.
        /// </param>
        /// <param name="pFirmwareTableEnumBuffer">A pointer to a buffer that receives the list of firmware table IDs.</param>
        /// <param name="BufferSize">The size of the pFirmwareTableEnumBuffer buffer, in bytes.</param>
        /// <returns>If the function succeeds, the return value is the number of bytes written to the buffer. If the buffer is too small, the return value is the required buffer size.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint EnumSystemFirmwareTables(
            uint FirmwareTableProviderSignature,
            IntPtr pFirmwareTableEnumBuffer,
            uint BufferSize);

        /// <summary>
        /// Retrieves the specified firmware table from the firmware table provider.
        /// </summary>
        /// <param name="FirmwareTableProviderSignature">The identifier of the firmware table provider (e.g., 0x424D5352 for RSMB).</param>
        /// <param name="FirmwareTableID">The identifier of the firmware table. 0x00000000 for the raw SMBIOS table.</param>
        /// <param name="pFirmwareTableBuffer">A pointer to a buffer that receives the requested firmware table.</param>
        /// <param name="BufferSize">The size of the pFirmwareTableBuffer buffer, in bytes.</param>
        /// <returns>If the function succeeds, the return value is the number of bytes written to the buffer. If the buffer is too small, the return value is the required buffer size.</returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetSystemFirmwareTable(
            uint FirmwareTableProviderSignature,
            uint FirmwareTableID,
            IntPtr pFirmwareTableBuffer,
            uint BufferSize);
    }
}
