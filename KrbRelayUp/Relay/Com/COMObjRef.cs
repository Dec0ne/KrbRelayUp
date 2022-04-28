//    This file is part of OleViewDotNet.
//    Copyright (C) James Forshaw 2014, 2017
//
//    OleViewDotNet is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    OleViewDotNet is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with OleViewDotNet.  If not, see <http://www.gnu.org/licenses/>.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace KrbRelayUp.Relay.Com
{
    [Flags]
    public enum COMObjrefFlags
    {
        None = 0,
        Standard = 1,
        Handler = 2,
        Custom = 4,
        Extended = 8,
    }

    public enum RpcAuthnService : short
    {
        None = 0,
        DCEPrivate = 1,
        DCEPublic = 2,
        DECPublic = 4,
        GSS_Negotiate = 9,
        WinNT = 10,
        GSS_SChannel = 14,
        GSS_Kerberos = 16,
        DPA = 17,
        MSN = 18,
        Digest = 21,
        Kernel = 20,
        NegoExtender = 30,
        PKU2U = 31,
        LiveSSP = 32,
        LiveXPSSP = 35,
        MSOnline = 82,
        MQ = 100,
        Default = -1,
    }

    // Note that most of these won't actually work.
    public enum RpcTowerId : short
    {
        None = 0,
        DNetNSP = 0x04, // ncacn_dnet_dsp
        Tcp = 0x07,     // ncacg_ip_tcp
        Udp = 0x08,     // ncacn_ip_udp
        NetbiosTcp = 0x09, // ncacn_nb_tcp
        Spx = 0x0C,         // ncacn_spx
        NetbiosIpx = 0xD,   // ncacn_np_ipx
        Ipx = 0x0E,         // ncacg_ipx
        NamedPipe = 0xF,    // ncacn_np
        LRPC = 0x10,        // ncalrpc
        NetBIOS = 0x13,     // ncacn_nb_nb
        AppleTalkDSP = 0x16,// ncacn_at_dsp
        AppleTalkDDP = 0x17,// ncacg_at_ddp
        BanyanVinesSPP = 0x1A, // ncacn_vns_spp
        MessageQueue = 0x1D,   // ncadg_mq
        Http = 0x1F,           // ncacn_http
        Container = 0x21,      // ncacn_hvsocket
        StringBinding = -1,
    }

    public class COMStringBinding
    {
        public RpcTowerId TowerId { get; set; }
        public string NetworkAddr { get; set; }

        public COMStringBinding() : this(0, string.Empty)
        {
        }

        public COMStringBinding(RpcTowerId tower_id, string network_addr)
        {
            TowerId = tower_id;
            NetworkAddr = network_addr;
        }

        internal COMStringBinding(BinaryReader reader, bool direct_string)
        {
            if (direct_string)
            {
                try
                {
                    TowerId = RpcTowerId.StringBinding;
                    NetworkAddr = reader.ReadZString();
                }
                catch (EndOfStreamException)
                {
                    NetworkAddr = string.Empty;
                }
            }
            else
            {
                TowerId = (RpcTowerId)reader.ReadInt16();
                if (TowerId != RpcTowerId.None)
                {
                    NetworkAddr = reader.ReadZString();
                }
                else
                {
                    NetworkAddr = string.Empty;
                }
            }
        }

        public void ToWriter(BinaryWriter writer)
        {
            writer.Write((short)TowerId);
            if (TowerId != 0)
            {
                writer.WriteZString(NetworkAddr);
            }
        }

        public override string ToString()
        {
            return $"TowerId: {TowerId} - NetworkAddr: {NetworkAddr}";
        }

        internal COMStringBinding Clone()
        {
            return (COMStringBinding)MemberwiseClone();
        }
    }

    public class COMSecurityBinding
    {
        public RpcAuthnService AuthnSvc { get; set; }
        public string PrincName { get; set; }

        public COMSecurityBinding() : this(0, string.Empty)
        {
        }

        public COMSecurityBinding(RpcAuthnService authn_svc, string princ_name)
        {
            AuthnSvc = authn_svc;
            PrincName = princ_name;
        }

        internal COMSecurityBinding(BinaryReader reader)
        {
            AuthnSvc = (RpcAuthnService)reader.ReadInt16();
            if (AuthnSvc != 0)
            {
                // Reserved
                reader.ReadInt16();
                PrincName = reader.ReadZString();
            }
            else
            {
                PrincName = string.Empty;
            }
        }

        public void ToWriter(BinaryWriter writer)
        {
            writer.Write((short)AuthnSvc);
            if (AuthnSvc != 0)
            {
                writer.Write((ushort)0xFFFF);
                writer.WriteZString(PrincName);
            }
        }

        public override string ToString()
        {
            return $"AuthnSvc: {AuthnSvc} - PrincName: {PrincName}";
        }

        internal COMSecurityBinding Clone()
        {
            return (COMSecurityBinding)MemberwiseClone();
        }
    }

    internal class COMDualStringArray
    {
        public List<COMStringBinding> StringBindings { get; private set; }
        public List<COMSecurityBinding> SecurityBindings { get; private set; }

        public COMDualStringArray()
        {
            StringBindings = new List<COMStringBinding>();
            SecurityBindings = new List<COMSecurityBinding>();
        }

        private void ReadEntries(BinaryReader new_reader, int sec_offset, bool direct_string)
        {
            COMStringBinding str = new COMStringBinding(new_reader, direct_string);
            if (direct_string)
            {
                StringBindings.Add(str);
            }
            else
            {
                while (str.TowerId != 0)
                {
                    StringBindings.Add(str);
                    str = new COMStringBinding(new_reader, direct_string);
                }
            }

            new_reader.BaseStream.Position = sec_offset * 2;
            COMSecurityBinding sec = new COMSecurityBinding(new_reader);
            while (sec.AuthnSvc != 0)
            {
                SecurityBindings.Add(sec);
                sec = new COMSecurityBinding(new_reader);
            }
        }

        //public COMDualStringArray(IntPtr ptr, NtProcess process, bool direct_string) : this()
        //{
        //    int num_entries = process.ReadMemory<ushort>(ptr.ToInt64());
        //    int sec_offset = process.ReadMemory<ushort>(ptr.ToInt64() + 2);
        //    if (num_entries > 0)
        //    {
        //        MemoryStream stm = new MemoryStream(process.ReadMemory(ptr.ToInt64() + 4, num_entries * 2));
        //        ReadEntries(new BinaryReader(stm), sec_offset, direct_string);
        //    }
        //}

        internal COMDualStringArray(BinaryReader reader) : this()
        {
            int num_entries = reader.ReadUInt16();
            int sec_offset = reader.ReadUInt16();

            if (num_entries > 0)
            {
                MemoryStream stm = new MemoryStream(reader.ReadAll(num_entries * 2));
                BinaryReader new_reader = new BinaryReader(stm);
                ReadEntries(new_reader, sec_offset, false);
            }
        }

        public void ToWriter(BinaryWriter writer)
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter new_writer = new BinaryWriter(stm);
            if (StringBindings.Count > 0)
            {
                foreach (COMStringBinding str in StringBindings)
                {
                    str.ToWriter(new_writer);
                }
                new COMStringBinding().ToWriter(new_writer);
            }
            ushort ofs = (ushort)(stm.Position / 2);
            if (SecurityBindings.Count > 0)
            {
                foreach (COMSecurityBinding sec in SecurityBindings)
                {
                    sec.ToWriter(new_writer);
                }
                new COMSecurityBinding().ToWriter(new_writer);
            }
            writer.Write((ushort)(stm.Length / 2));
            writer.Write(ofs);
            writer.Write(stm.ToArray());
        }

        internal COMDualStringArray Clone()
        {
            COMDualStringArray ret = new COMDualStringArray();
            ret.StringBindings.AddRange(StringBindings.Select(b => b.Clone()));
            ret.SecurityBindings.AddRange(SecurityBindings.Select(b => b.Clone()));
            return ret;
        }
    }

    public abstract class COMObjRef
    {
        public const int OBJREF_MAGIC = 0x574f454d;

        public Guid Iid { get; set; }

        public COMObjrefFlags Flags
        {
            get
            {
                if (this is COMObjRefCustom)
                {
                    return COMObjrefFlags.Custom;
                }
                else if (this is COMObjRefHandler)
                {
                    return COMObjrefFlags.Handler;
                }
                else if (this is COMObjRefStandard)
                {
                    return COMObjrefFlags.Standard;
                }
                else
                {
                    return COMObjrefFlags.None;
                }
            }
        }

        public byte[] ToArray()
        {
            MemoryStream stm = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(stm);
            writer.Write(OBJREF_MAGIC);
            writer.Write((int)Flags);
            writer.Write(Iid);
            Serialize(writer);
            return stm.ToArray();
        }

        public string ToMoniker()
        {
            return $"objref:{Convert.ToBase64String(ToArray())}:";
        }

        protected abstract void Serialize(BinaryWriter writer);

        protected COMObjRef(Guid iid)
        {
            Iid = iid;
        }

        public static COMObjRef FromArray(byte[] arr)
        {
            MemoryStream stm = new MemoryStream(arr);
            BinaryReader reader = new BinaryReader(stm);
            int magic = reader.ReadInt32();
            if (magic != OBJREF_MAGIC)
            {
                throw new ArgumentException("Invalid OBJREF Magic");
            }

            COMObjrefFlags flags = (COMObjrefFlags)reader.ReadInt32();
            Guid iid = reader.ReadGuid();
            switch (flags)
            {
                case COMObjrefFlags.Custom:
                    return new COMObjRefCustom(reader, iid);

                case COMObjrefFlags.Standard:
                    return new COMObjRefStandard(reader, iid);

                case COMObjrefFlags.Handler:
                    return new COMObjRefHandler(reader, iid);

                case COMObjrefFlags.Extended:
                default:
                    throw new ArgumentException("Invalid OBJREF Type Flags");
            }
        }
    }

    public class COMObjRefCustom : COMObjRef
    {
        public Guid Clsid { get; set; }
        public int Reserved { get; set; }
        public byte[] ExtensionData { get; set; }
        public byte[] ObjectData { get; set; }

        //public COMObjRefCustom()
        //    : base(COMInterfaceEntry.IID_IUnknown)
        //{
        //    ObjectData = new byte[0];
        //    ExtensionData = new byte[0];
        //}

        internal COMObjRefCustom(BinaryReader reader, Guid iid)
            : base(iid)
        {
            Clsid = reader.ReadGuid();
            // Size of extension data but can be 0.
            int extension = reader.ReadInt32();
            ExtensionData = new byte[extension];
            Reserved = reader.ReadInt32();
            if (extension > 0)
            {
                ExtensionData = reader.ReadAll(extension);
            }
            // Read to end of stream.
            ObjectData = reader.ReadBytes((int)(reader.BaseStream.Length - reader.BaseStream.Position));
        }

        protected override void Serialize(BinaryWriter writer)
        {
            writer.Write(Clsid);
            writer.Write(ExtensionData.Length);
            writer.Write(Reserved);
            writer.Write(ExtensionData);
            writer.Write(ObjectData);
        }
    }

    [Flags]
    public enum COMStdObjRefFlags
    {
        None = 0,
        NoPing = 0x1000
    }

    internal class COMStdObjRef
    {
        public COMStdObjRefFlags StdFlags { get; set; }
        public int PublicRefs { get; set; }
        public ulong Oxid { get; set; }
        public ulong Oid { get; set; }
        public Guid Ipid { get; set; }

        public COMStdObjRef()
        {
        }

        internal COMStdObjRef(BinaryReader reader)
        {
            StdFlags = (COMStdObjRefFlags)reader.ReadInt32();
            PublicRefs = reader.ReadInt32();
            Oxid = reader.ReadUInt64();
            Oid = reader.ReadUInt64();
            Ipid = reader.ReadGuid();
        }

        public void ToWriter(BinaryWriter writer)
        {
            writer.Write((int)StdFlags);
            writer.Write(PublicRefs);
            writer.Write(Oxid);
            writer.Write(Oid);
            writer.Write(Ipid);
        }

        internal COMStdObjRef Clone()
        {
            return (COMStdObjRef)MemberwiseClone();
        }
    }

    public class COMObjRefStandard : COMObjRef
    {
        internal COMStdObjRef _stdobjref;
        internal COMDualStringArray _stringarray;

        public COMStdObjRefFlags StdFlags { get => _stdobjref.StdFlags; set => _stdobjref.StdFlags = value; }
        public int PublicRefs { get => _stdobjref.PublicRefs; set => _stdobjref.PublicRefs = value; }
        public ulong Oxid { get => _stdobjref.Oxid; set => _stdobjref.Oxid = value; }
        public ulong Oid { get => _stdobjref.Oid; set => _stdobjref.Oid = value; }
        public Guid Ipid { get => _stdobjref.Ipid; set => _stdobjref.Ipid = value; }

        public List<COMStringBinding> StringBindings => _stringarray.StringBindings;
        public List<COMSecurityBinding> SecurityBindings => _stringarray.SecurityBindings;

        public int ProcessId => COMUtilities.GetProcessIdFromIPid(Ipid);

        public string ProcessName => COMUtilities.GetProcessNameById(ProcessId);

        public int ApartmentId => COMUtilities.GetApartmentIdFromIPid(Ipid);
        public string ApartmentName => COMUtilities.GetApartmentIdStringFromIPid(Ipid);

        internal COMObjRefStandard(BinaryReader reader, Guid iid)
            : base(iid)
        {
            _stdobjref = new COMStdObjRef(reader);
            _stringarray = new COMDualStringArray(reader);
        }

        protected COMObjRefStandard(Guid iid) : base(iid)
        {
        }

        protected COMObjRefStandard(COMObjRefStandard std) : base(std.Iid)
        {
            _stdobjref = std._stdobjref.Clone();
            _stringarray = std._stringarray.Clone();
        }

        public COMObjRefStandard() : base(Guid.Empty)
        {
            _stdobjref = new COMStdObjRef();
            _stringarray = new COMDualStringArray();
        }

        protected override void Serialize(BinaryWriter writer)
        {
            _stdobjref.ToWriter(writer);
            _stringarray.ToWriter(writer);
        }

        public COMObjRefHandler ToHandler(Guid clsid)
        {
            return new COMObjRefHandler(clsid, this);
        }
    }

    public class COMObjRefHandler : COMObjRefStandard
    {
        public Guid Clsid { get; set; }

        internal COMObjRefHandler(BinaryReader reader, Guid iid)
            : base(iid)
        {
            _stdobjref = new COMStdObjRef(reader);
            Clsid = reader.ReadGuid();
            _stringarray = new COMDualStringArray(reader);
        }

        internal COMObjRefHandler(Guid clsid, COMObjRefStandard std) : base(std)
        {
            Clsid = clsid;
        }

        public COMObjRefHandler() : base()
        {
        }

        protected override void Serialize(BinaryWriter writer)
        {
            _stdobjref.ToWriter(writer);
            writer.Write(Clsid);
            _stringarray.ToWriter(writer);
        }
    }
}