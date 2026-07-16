# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Tested so far:
#   Since DCOM is more high level, I'll always use the helper classes
#   ServerAlive
#   ServerAlive2
#   ComplexPing
#   SimplePing
#   RemoteCreateInstance
#   ResolveOxid
#   ResolveOxid2
#   RemoteActivation
#   RemRelease
#   RemoteGetClassObject
#
from __future__ import division
from __future__ import print_function

import pytest
import unittest
from unittest.mock import patch
from tests import RemoteTestCase
from tests.dcerpc import DCERPCTests

from impacket import ntlm
from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket.dcerpc.v5 import dcomrt
from impacket.dcerpc.v5.dcom import scmp, vds, oaut, comev, wmi


class DCOMLocalTests(unittest.TestCase):

    def test_idispatch_invoke_uses_variant_reference_values(self):
        class Dispatch:
            _iid = b'iid'

            def get_iPid(self):
                return b'ipid'

            def request(self, request, iid, uuid):
                self.sent_request = request
                return b'response'

        dispatch = Dispatch()
        var_ref_indexes = object()
        var_refs = object()
        request = {}

        with patch.object(oaut, 'IDispatch_Invoke', return_value=request):
            response = oaut.IDispatch.Invoke(
                dispatch, 1, 2, 3, object(), 1, var_ref_indexes, var_refs
            )

        self.assertEqual(b'response', response)
        self.assertIs(var_ref_indexes, request['rgVarRefIdx'])
        self.assertIs(var_refs, request['rgVarRef'])

    def test_wmi_cim_array_types_include_array_flag(self):
        type_names = (
            'SINT8', 'UINT8', 'SINT16', 'UINT16', 'SINT32', 'UINT32',
            'SINT64', 'UINT64', 'REAL32', 'REAL64', 'BOOLEAN', 'STRING',
            'DATETIME', 'REFERENCE', 'CHAR16', 'OBJECT',
        )

        for type_name in type_names:
            scalar = getattr(wmi.CIM_TYPE_ENUM, 'CIM_TYPE_%s' % type_name)
            array = getattr(wmi.CIM_TYPE_ENUM, 'CIM_ARRAY_%s' % type_name)
            self.assertEqual(wmi.CIM_ARRAY_FLAG | scalar.value, array.value)

    def test_extended_objref_initializes_signatures_and_element_count(self):
        objref = dcomrt.OBJREF_EXTENDED()

        self.assertEqual(0x4E535956, objref['Signature1'])
        self.assertEqual(1, objref['nElms'])
        self.assertEqual(0x4E535956, objref['Signature2'])

    def test_special_properties_reserved_fields_round_trip(self):
        properties = dcomrt.SpecialPropertiesData()
        properties['Reserved1'] = 1
        properties['Reserved2'] = 2
        properties['Reserved3_1'] = 3
        properties['Reserved3_2'] = 4
        properties['Reserved3_3'] = 5
        properties['Reserved3_4'] = 6
        properties['Reserved3_5'] = 7

        parsed = dcomrt.SpecialPropertiesData(properties.getData())

        self.assertEqual(1, parsed['Reserved1'])
        self.assertEqual(2, parsed['Reserved2'])
        self.assertEqual(3, parsed['Reserved3_1'])
        self.assertEqual(4, parsed['Reserved3_2'])
        self.assertEqual(5, parsed['Reserved3_3'])
        self.assertEqual(6, parsed['Reserved3_4'])
        self.assertEqual(7, parsed['Reserved3_5'])


class DCOMTests(DCERPCTests):

    string_binding = r"ncacn_ip_tcp:{0.machine}"
    authn = True
    authn_level = ntlm.NTLM_AUTH_PKT_INTEGRITY

    def test_ServerAlive(self):
        dce, rpctransport = self.connect()
        objExporter = dcomrt.IObjectExporter(dce)
        objExporter.ServerAlive()

    def test_ServerAlive2(self):
        dce, rpctransport = self.connect()
        objExporter = dcomrt.IObjectExporter(dce)
        objExporter.ServerAlive2()

    def test_ComplexPing_SimplePing(self):
        dce, rpctransport = self.connect()
        objExporter = dcomrt.IObjectExporter(dce)
        resp = objExporter.ComplexPing()
        objExporter.SimplePing(resp['pSetId'])

    def test_ResolveOxid(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        objExporter = dcomrt.IObjectExporter(dce)
        objExporter.ResolveOxid(iInterface.get_oxid(), (7,))

    def test_ResolveOxid2(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IActivation(dce)
        iInterface = scm.RemoteActivation(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        objExporter = dcomrt.IObjectExporter(dce)
        objExporter.ResolveOxid2(iInterface.get_oxid(), (7,))

    def test_RemoteActivation(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IActivation(dce)
        scm.RemoteActivation(comev.CLSID_EventSystem, comev.IID_IEventSystem)

    def test_RemoteGetClassObject(self):
        IID_IClassFactory = uuidtup_to_bin(('00000001-0000-0000-C000-000000000046', '0.0'))
        dcom = dcomrt.DCOMConnection(
            self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash,
            authLevel=self.authn_level
        )
        try:
            scm = dcomrt.IRemoteSCMActivator(dcom.get_dce_rpc())
            iInterface = scm.RemoteGetClassObject(comev.CLSID_EventSystem, IID_IClassFactory)
            iInterface.RemRelease()
        finally:
            dcom.disconnect()

    def test_RemoteCreateInstance(self):
        dce, rpctransport = self.connect()

        scm = dcomrt.IRemoteSCMActivator(dce)
        scm.RemoteCreateInstance(comev.CLSID_EventSystem, comev.IID_IEventSystem)

    @pytest.mark.skip
    def test_scmp(self):
        dce, rpctransport = self.connect()

        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(scmp.CLSID_ShadowCopyProvider, scmp.IID_IVssSnapshotMgmt)
        iVssSnapshotMgmt = scmp.IVssSnapshotMgmt(iInterface)
        # iVssSnapshotMgmt.RemRelease()

        iVssEnumMgmtObject = iVssSnapshotMgmt.QueryVolumesSupportedForSnapshots(scmp.IID_ShadowCopyProvider, 31)
        iVssEnumMgmtObject.Next(10)
        # iVssEnumObject = iVssSnapshotMgmt.QuerySnapshotsByVolume('C:\x00')

        # iProviderMgmtInterface = iVssSnapshotMgmt.GetProviderMgmtInterface()
        # enumObject =iProviderMgmtInterface.QueryDiffAreasOnVolume('C:\x00')
        # iVssSnapshotMgmt.RemQueryInterface(1, (scmp.IID_IVssEnumMgmtObject,))
        # iVssSnapshotMgmt.RemAddRef()
        # iVssSnapshotMgmt = dcom.hRemoteCreateInstance(dce, scmp.CLSID_ShadowCopyProvider, dcom.IID_IRemUnknown)

        # iVssEnumMgmtObject.RemQueryInterface(1, (scmp.IID_IVssEnumMgmtObject,))

    @pytest.mark.skip
    def test_vds(self):
        dce, rpctransport = self.connect()

        # objExporter = dcom.IObjectExporter(dce)
        # objExporter.ComplexPing()
        # objExporter.ComplexPing()

        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(vds.CLSID_VirtualDiskService, vds.IID_IVdsServiceInitialization)
        serviceInitialization = vds.IVdsServiceInitialization(iInterface)
        serviceInitialization.Initialize()

        iInterface = serviceInitialization.RemQueryInterface(1, (vds.IID_IVdsService,))
        vdsService = vds.IVdsService(iInterface)

        resp = vdsService.IsServiceReady()
        while resp['ErrorCode'] == 1:
            print("Waiting.. ")
            resp = vdsService.IsServiceReady()

        vdsService.WaitForServiceReady()
        vdsService.GetProperties()
        enumObject = vdsService.QueryProviders(1)
        interfaces = enumObject.Next(1)
        iii = interfaces[0].RemQueryInterface(1, (vds.IID_IVdsProvider,))
        provider = vds.IVdsProvider(iii)
        resp = provider.GetProperties()
        resp.dump()

    @pytest.mark.skip
    def test_oaut(self):
        dce, rpctransport = self.connect()
        IID_IDispatch = string_to_bin('00020400-0000-0000-C000-000000000046')
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(string_to_bin('4E14FBA2-2E22-11D1-9964-00C04FBBB345'), IID_IDispatch)
        iDispatch = oaut.IDispatch(iInterface)
        kk = iDispatch.GetTypeInfoCount()
        kk.dump()
        iTypeInfo = iDispatch.GetTypeInfo()
        iTypeInfo.GetTypeAttr()

    @pytest.mark.skip
    def test_ie(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)

        #iInterface = scm.RemoteCreateInstance(string_to_bin('0002DF01-0000-0000-C000-000000000046'), ie.IID_WebBrowser)
        iInterface = scm.RemoteCreateInstance(string_to_bin('72C24DD5-D70A-438B-8A42-98424B88AFB8'), dcomrt.IID_IRemUnknown)

        #iDispatch = ie.IWebBrowser(iInterface)
        #resp = iDispatch.GetIDsOfNames(('Navigate',))
        #print(resp)

        #iTypeInfo = iDispatch.GetTypeInfo()
        #resp = iTypeInfo.GetTypeAttr()
        #resp.dump()
        #for i in range(0,resp['ppTypeAttr']['cFuncs']):
            #resp = iTypeInfo.GetFuncDesc(i)
            #resp.dump()
            #resp2 = iTypeInfo.GetNames(resp['ppFuncDesc']['memid'])
            #print resp2['rgBstrNames'][0]['asData']
            #resp = iTypeInfo.GetDocumentation(resp['ppFuncDesc']['memid'])
            #print(resp['pBstrName']['asData'])
        #iEventSystem.get_EventObjectChangeEventClassID()
        #print("ACA")
        #iTypeInfo.RemRelease()
        #iDispatch.RemRelease()


@pytest.mark.remote
class DCOMConnectionTests(RemoteTestCase, unittest.TestCase):

    def setUp(self):
        self.set_transport_config()

    def test_RemQueryInterface(self):
        dcom = dcomrt.DCOMConnection(self.machine, self.username, self.password, self.domain)
        iInterface = dcom.CoCreateInstanceEx(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        iEventSystem = comev.IEventSystem(iInterface)
        iEventSystem.RemQueryInterface(1, (comev.IID_IEventSystem,))
        dcom.disconnect()

    def test_RemRelease(self):
        dcom = dcomrt.DCOMConnection(self.machine, self.username, self.password, self.domain)
        iInterface = dcom.CoCreateInstanceEx(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        iEventSystem = comev.IEventSystem(iInterface)
        iEventSystem.RemRelease()
        dcom.disconnect()

    @pytest.mark.remote
    def test_comev(self):
        dcom = dcomrt.DCOMConnection(self.machine, self.username, self.password, self.domain, self.lmhash, self.nthash)
        iInterface = dcom.CoCreateInstanceEx(comev.CLSID_EventSystem, comev.IID_IEventSystem)

        #scm = dcomrt.IRemoteSCMActivator(dce)
        
        #iInterface = scm.RemoteCreateInstance(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        #iInterface = scm.RemoteCreateInstance(comev.CLSID_EventSystem,oaut.IID_IDispatch)
        iDispatch = oaut.IDispatch(iInterface)  # noqa
        #scm = dcomrt.IRemoteSCMActivator(dce)
        #resp = iDispatch.GetIDsOfNames(('Navigate\x00', 'ExecWB\x00'))
        #resp.dump()
        iEventSystem = comev.IEventSystem(iInterface)
        iTypeInfo = iEventSystem.GetTypeInfo()
        resp = iTypeInfo.GetTypeAttr()
        #resp.dump()
        for i in range(1,resp['ppTypeAttr']['cFuncs']):
            resp = iTypeInfo.GetFuncDesc(i)
            #resp.dump()
            iTypeInfo.GetNames(resp['ppFuncDesc']['memid'])
            iTypeInfo.GetDocumentation(resp['ppFuncDesc']['memid'])
        #iEventSystem.get_EventObjectChangeEventClassID()
        iEventSystem.RemRelease()
        iTypeInfo.RemRelease()

        objCollection = iEventSystem.Query('EventSystem.EventSubscriptionCollection', 'ALL')

        objCollection.get_Count()

        evnObj = objCollection.get_NewEnum()
        for i in range(3):
            iUnknown = evnObj.Next(1)[0]
            es = iUnknown.RemQueryInterface(1, (comev.IID_IEventSubscription3,))
            es = comev.IEventSubscription3(es)

            #es.get_SubscriptionID()
            print(es.get_SubscriptionName()['pbstrSubscriptionName']['asData'])
            ##es.get_PublisherID()
            #es.get_EventClassID()
            #es.get_MethodName()
            ##es.get_SubscriberCLSID()
            #es.get_SubscriberInterface()
            #es.get_PerUser()
            #es.get_OwnerSID()
            #es.get_Enabled()
            ##es.get_Description()
            ##es.get_MachineName()
            ##es.GetPublisherProperty()
            #es.GetPublisherPropertyCollection()
            ##es.GetSubscriberProperty()
            #es.GetSubscriberPropertyCollection()
            #es.get_InterfaceID()
            es.RemRelease()

        objCollection = iEventSystem.Query('EventSystem.EventClassCollection', 'ALL')
        objCollection.get_Count()

        #objCollection.get_Item('EventClassID={D5978630-5B9F-11D1-8DD2-00AA004ABD5E}')
        evnObj = objCollection.get_NewEnum()
        for i in range(3):

            iUnknown = evnObj.Next(1)[0]

            ev = iUnknown.RemQueryInterface(1, (comev.IID_IEventClass2,))
            ev = comev.IEventClass2(ev)

            ev.get_EventClassID() 
            #ev.get_EventClassName() 
            #ev.get_OwnerSID() 
            #ev.get_FiringInterfaceID() 
            #ev.get_Description() 
            #try:
            #    ev.get_TypeLib() 
            #except:
            #    pass

            #ev.get_PublisherID()
            #ev.get_MultiInterfacePublisherFilterCLSID()
            #ev.get_AllowInprocActivation()
            #ev.get_FireInParallel()
            ev.RemRelease()

        print("="*80)

        dcom.disconnect()
        #eventSubscription.get_SubscriptionID()


@pytest.mark.remote
class DCOMTestsTCPTransport(DCOMTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class DCOMTestsTCPTransport(DCOMTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
