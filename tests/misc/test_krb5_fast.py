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
import datetime
import os
import tempfile
from unittest import TestCase, mock

from pyasn1.codec.der import encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AP_REQ, AS_REQ, AS_REP, TGS_REQ, TGS_REP, Authenticator, EncryptedData, EncASRepPart, EncTGSRepPart,
    ETYPE_INFO2, KDC_REQ_BODY, KRB_ERROR, KrbFastReq, KrbFastResponse,
    METHOD_DATA, KERB_PA_PAC_REQUEST, PA_ENC_TS_ENC, PA_FX_FAST_REQUEST, PA_FX_FAST_REPLY,
    Ticket, seq_set, seq_set_iter,
)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, InvalidChecksum, _enctype_table, cf2, make_checksum, verify_checksum
from impacket.krb5.fast import ARMOR_CACHE_ENV, FastContext, decode, get_padata
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT, getKerberosTGS, _recvExact
from impacket.krb5.types import KerberosTime, Principal


REALM = 'EXAMPLE.COM'
PASSWORD = 'example-password'
ARMOR_KEY = Key(18, bytes(range(32)))
NOW = datetime.datetime.now(datetime.timezone.utc)


def principal(value):
    return Principal(value, type=constants.PrincipalNameType.NT_PRINCIPAL.value)


def ticket(service='krbtgt/' + REALM):
    result = Ticket()
    result['tkt-vno'] = 5
    result['realm'] = REALM
    seq_set(result, 'sname', principal(service).components_to_asn1)
    result['enc-part'] = noValue
    result['enc-part']['etype'] = 18
    result['enc-part']['cipher'] = b'opaque-ticket'
    return result


def request(enctype=18):
    result = AS_REQ()
    result['pvno'] = 5
    result['msg-type'] = 10
    body = seq_set(result, 'req-body')
    body['kdc-options'] = constants.encodeFlags([])
    seq_set(body, 'cname', principal('user').components_to_asn1)
    seq_set(body, 'sname', principal('krbtgt/' + REALM).components_to_asn1)
    body['realm'] = REALM
    body['till'] = KerberosTime.to_asn1(NOW + datetime.timedelta(hours=1))
    body['nonce'] = 123
    seq_set_iter(body, 'etype', [enctype])
    seq_set_iter(result, 'padata', [])
    return result


class FakeKDC:
    def __init__(self, bad_nonce=False, bad_finished=False, bad_challenge=False, s2kparams=None, force_continue=False):
        self.requests = []
        self.bad_nonce = bad_nonce
        self.bad_finished = bad_finished
        self.bad_challenge = bad_challenge
        self.s2kparams = s2kparams
        self.force_continue = force_continue

    def __call__(self, data, domain, host):
        req = decode(data, AS_REQ())
        envelope = decode(get_padata(req['padata'], 136), PA_FX_FAST_REQUEST())['armored-data']
        ap_req = decode(envelope['armor']['armor-value'].asOctets(), AP_REQ())
        auth = decode(_enctype_table[18].decrypt(ARMOR_KEY, 11,
                      ap_req['authenticator']['cipher'].asOctets()), Authenticator())
        subkey = Key(int(auth['subkey']['keytype']), auth['subkey']['keyvalue'].asOctets())
        armor = cf2(subkey.enctype, subkey, ARMOR_KEY, b'subkeyarmor', b'ticketarmor')
        cipher = _enctype_table[armor.enctype]
        checksum_type = FastContext.checksum_type(armor.enctype)
        verify_checksum(checksum_type, armor, 50,
                        encoder.encode(req['req-body'].clone(tagSet=KDC_REQ_BODY.tagSet, cloneValueFlag=True)),
                        envelope['req-checksum']['checksum'].asOctets())
        inner = decode(cipher.decrypt(armor, 51, envelope['enc-fast-req']['cipher'].asOctets()), KrbFastReq())
        self.requests.append(inner)
        enctype = int(inner['req-body']['etype'][0])
        key = _enctype_table[enctype].string_to_key(PASSWORD, (REALM + 'user').encode(), self.s2kparams)
        preauth = any(int(pa['padata-type']) == 138 for pa in inner['padata'])
        fast = KrbFastResponse()
        fast['nonce'] = int(inner['req-body']['nonce']) + int(self.bad_nonce)
        info = ETYPE_INFO2()
        info[0] = noValue
        info[0]['etype'] = enctype
        info[0]['salt'] = REALM + 'user'
        if self.s2kparams is not None:
            info[0]['s2kparams'] = self.s2kparams
        methods = [FastContext.padata(19, encoder.encode(info))]
        error_code = 25
        if preauth:
            challenge = decode(get_padata(inner['padata'], 138), EncryptedData())
            challenge_key = cf2(armor.enctype, armor, key, b'clientchallengearmor', b'challengelongterm')
            try:
                decode(cipher.decrypt(challenge_key, 54, challenge['cipher'].asOctets()), PA_ENC_TS_ENC())
            except InvalidChecksum:
                preauth = False
                error_code = 24
            if preauth and self.force_continue:
                preauth = False
                error_code = 91

        if not preauth:
            reply = KRB_ERROR()
            reply['pvno'] = 5
            reply['msg-type'] = 30
            reply['stime'] = KerberosTime.to_asn1(NOW)
            reply['susec'] = 0
            reply['error-code'] = error_code
            reply['realm'] = REALM
            seq_set(reply, 'sname', principal('krbtgt/' + REALM).components_to_asn1)
            methods.append(FastContext.padata(137, encoder.encode(reply)))
            methods.append(FastContext.padata(133, b'cookie'))
        else:
            reply = AS_REP()
            reply['pvno'] = 5
            reply['msg-type'] = 11
            reply['crealm'] = REALM
            seq_set(reply, 'cname', principal('user').components_to_asn1)
            reply['ticket'] = ticket().clone(tagSet=reply['ticket'].tagSet, cloneValueFlag=True)
            strengthen = Key(enctype, bytes([7]) * _enctype_table[enctype].keysize)
            fast['strengthen-key'] = noValue
            fast['strengthen-key']['keytype'] = enctype
            fast['strengthen-key']['keyvalue'] = strengthen.contents
            finished = seq_set(fast, 'finished')
            finished['timestamp'] = KerberosTime.to_asn1(NOW)
            finished['usec'] = 0
            finished['crealm'] = REALM
            seq_set(finished, 'cname', principal('user').components_to_asn1)
            finished['ticket-checksum'] = noValue
            finished['ticket-checksum']['cksumtype'] = checksum_type
            finished['ticket-checksum']['checksum'] = make_checksum(
                checksum_type, armor, 53, b'wrong' if self.bad_finished else encoder.encode(ticket()))
            challenge_key = cf2(armor.enctype, armor, key, b'kdcchallengearmor', b'challengelongterm')
            timestamp = PA_ENC_TS_ENC()
            timestamp['patimestamp'] = KerberosTime.to_asn1(NOW)
            timestamp['pausec'] = 0
            challenge = EncryptedData()
            challenge['etype'] = armor.enctype
            encrypted = cipher.encrypt(challenge_key, 55, encoder.encode(timestamp), None)
            challenge['cipher'] = encrypted[:-1] + bytes([encrypted[-1] ^ 1]) if self.bad_challenge else encrypted
            methods.append(FastContext.padata(138, encoder.encode(challenge)))
            part = EncASRepPart()
            part['key'] = noValue
            part['key']['keytype'] = enctype
            part['key']['keyvalue'] = bytes([9]) * _enctype_table[enctype].keysize
            seq_set_iter(part, 'last-req', [])
            part['nonce'] = int(inner['req-body']['nonce'])
            part['flags'] = constants.encodeFlags([constants.TicketFlags.initial.value])
            for name in ('authtime', 'starttime'):
                part[name] = KerberosTime.to_asn1(NOW)
            part['endtime'] = KerberosTime.to_asn1(NOW + datetime.timedelta(hours=1))
            part['srealm'] = REALM
            seq_set(part, 'sname', principal('krbtgt/' + REALM).components_to_asn1)
            reply_key = cf2(enctype, strengthen, key, b'strengthenkey', b'replykey')
            reply['enc-part'] = noValue
            reply['enc-part']['etype'] = enctype
            reply['enc-part']['cipher'] = _enctype_table[enctype].encrypt(reply_key, 3, encoder.encode(part), None)
        seq_set_iter(fast, 'padata', methods)
        choice = PA_FX_FAST_REPLY()
        choice['armored-data'] = noValue
        choice['armored-data']['enc-fast-rep'] = noValue
        choice['armored-data']['enc-fast-rep']['etype'] = armor.enctype
        choice['armored-data']['enc-fast-rep']['cipher'] = cipher.encrypt(armor, 52, encoder.encode(fast), None)
        methods = [FastContext.padata(136, encoder.encode(choice))]
        if int(reply['msg-type']) == 30:
            encoded = METHOD_DATA()
            seq_set_iter_container(encoded, methods)
            reply['e-data'] = encoder.encode(encoded)
        else:
            seq_set_iter(reply, 'padata', methods)
        return encoder.encode(reply)


def seq_set_iter_container(seq, values):
    for i, value in enumerate(values):
        seq[i] = value


class FakeTGSKDC:
    def __init__(self, session_key, missing_strengthen=False, bad_nonce=False, service_override=None):
        self.session_key = session_key
        self.missing_strengthen = missing_strengthen
        self.bad_nonce = bad_nonce
        self.service_override = service_override
        self.calls = 0
        self.raw_reply = None

    def __call__(self, data, domain, host):
        self.calls += 1
        req = decode(data, TGS_REQ())
        if not any(int(pa['padata-type']) == 136 for pa in req['padata']):
            raise KerberosError(12)
        ap_bytes = get_padata(req['padata'], 1)
        ap = decode(ap_bytes, AP_REQ())
        cipher = _enctype_table[self.session_key.enctype]
        auth = decode(cipher.decrypt(self.session_key, 7, ap['authenticator']['cipher'].asOctets()), Authenticator())
        checksum_type = FastContext.checksum_type(self.session_key.enctype)
        body = encoder.encode(req['req-body'].clone(tagSet=KDC_REQ_BODY.tagSet, cloneValueFlag=True))
        verify_checksum(checksum_type, self.session_key, 6, body, auth['cksum']['checksum'].asOctets())
        subkey = Key(int(auth['subkey']['keytype']), auth['subkey']['keyvalue'].asOctets())
        armor = cf2(subkey.enctype, subkey, self.session_key, b'subkeyarmor', b'ticketarmor')
        envelope = decode(get_padata(req['padata'], 136), PA_FX_FAST_REQUEST())['armored-data']
        if envelope['armor'].hasValue():
            raise AssertionError('Implicit TGS armor must not contain a separate AP-REQ')
        verify_checksum(checksum_type, armor, 50, ap_bytes, envelope['req-checksum']['checksum'].asOctets())
        inner = decode(cipher.decrypt(armor, 51, envelope['enc-fast-req']['cipher'].asOctets()), KrbFastReq())
        if any(int(pa['padata-type']) == 1 for pa in inner['padata']):
            raise AssertionError('PA-TGS-REQ must remain outside FAST')
        service = self.service_override or '/'.join(map(str, inner['req-body']['sname']['name-string']))
        reply = TGS_REP()
        reply['pvno'] = 5
        reply['msg-type'] = 13
        reply['crealm'] = REALM
        seq_set(reply, 'cname', principal('user').components_to_asn1)
        reply['ticket'] = ticket(service).clone(tagSet=reply['ticket'].tagSet, cloneValueFlag=True)
        fast = KrbFastResponse()
        fast['nonce'] = int(inner['req-body']['nonce']) + int(self.bad_nonce)
        seq_set_iter(fast, 'padata', [])
        strengthen = Key(subkey.enctype, bytes([7]) * cipher.keysize)
        if not self.missing_strengthen:
            fast['strengthen-key'] = noValue
            fast['strengthen-key']['keytype'] = strengthen.enctype
            fast['strengthen-key']['keyvalue'] = strengthen.contents
        finished = seq_set(fast, 'finished')
        finished['timestamp'] = KerberosTime.to_asn1(NOW)
        finished['usec'] = 0
        finished['crealm'] = REALM
        seq_set(finished, 'cname', principal('user').components_to_asn1)
        finished['ticket-checksum'] = noValue
        finished['ticket-checksum']['cksumtype'] = checksum_type
        finished['ticket-checksum']['checksum'] = make_checksum(checksum_type, armor, 53, encoder.encode(ticket(service)))
        choice = PA_FX_FAST_REPLY()
        encrypted = seq_set(seq_set(choice, 'armored-data'), 'enc-fast-rep')
        encrypted['etype'] = armor.enctype
        encrypted['cipher'] = cipher.encrypt(armor, 52, encoder.encode(fast), None)
        seq_set_iter(reply, 'padata', [FastContext.padata(136, encoder.encode(choice))])
        part = EncTGSRepPart()
        part['key'] = noValue
        part['key']['keytype'] = 17
        part['key']['keyvalue'] = bytes([6]) * 16
        seq_set_iter(part, 'last-req', [])
        part['nonce'] = int(inner['req-body']['nonce'])
        part['flags'] = constants.encodeFlags([])
        for name in ('authtime', 'starttime'):
            part[name] = KerberosTime.to_asn1(NOW)
        part['endtime'] = KerberosTime.to_asn1(NOW + datetime.timedelta(hours=1))
        part['srealm'] = REALM
        seq_set(part, 'sname', principal(service).components_to_asn1)
        reply_key = cf2(subkey.enctype, strengthen, subkey, b'strengthenkey', b'replykey')
        reply['enc-part'] = noValue
        reply['enc-part']['etype'] = reply_key.enctype
        reply['enc-part']['cipher'] = cipher.encrypt(reply_key, 9, encoder.encode(part), None)
        self.raw_reply = encoder.encode(reply)
        return self.raw_reply


class FASTTests(TestCase):
    def context(self, enctype=18):
        return FastContext.for_as(ticket(), principal('host$@' + REALM), ARMOR_KEY, enctype)

    def get_tgt(self, kdc, enctype=18, password=PASSWORD, aes_key=b'', nt_hash=b''):
        context = self.context(enctype)
        with mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=kdc), \
             mock.patch('impacket.krb5.kerberosv5.FastContext.from_ccache', return_value=context):
            return getKerberosTGT(principal('user'), password, REALM, b'', nt_hash, aesKey=aes_key,
                                  requestPAC=False, armorCache='armor.ccache')

    def test_as_password_cache_and_cookies(self):
        kdc = FakeKDC()
        raw, cipher, reply_key, session_key = self.get_tgt(kdc)
        self.assertEqual(len(kdc.requests), 2)
        self.assertEqual(get_padata(kdc.requests[1]['padata'], 133), b'cookie')
        self.assertFalse(bool(decode(get_padata(kdc.requests[1]['padata'], 128), KERB_PA_PAC_REQUEST())['include-pac']))
        self.assertEqual(session_key.contents, bytes([9]) * 32)
        cache = CCache()
        cache.fromTGT(raw, reply_key, session_key)
        self.assertEqual(cache.credentials[0]['client'].toPrincipal().components, ['user'])

    def test_mixed_aes_key(self):
        key = _enctype_table[17].string_to_key(PASSWORD, (REALM + 'user').encode(), None)
        result = self.get_tgt(FakeKDC(), 17, password='', aes_key=key.contents)
        self.assertEqual(result[3].enctype, 17)

    def test_password_uses_kdc_s2k_parameters(self):
        self.assertEqual(self.get_tgt(FakeKDC(s2kparams=b'\x00\x00\x00\x02'))[3].enctype, 18)

    def test_rc4_hash_with_aes_armor_ticket(self):
        key = _enctype_table[23].string_to_key(PASSWORD, b'', None)
        self.assertEqual(self.get_tgt(FakeKDC(), 23, password='', nt_hash=key.contents)[3].enctype, 23)

    def test_continuation_is_bounded(self):
        kdc = FakeKDC(force_continue=True)
        with self.assertRaises(KerberosError) as error:
            self.get_tgt(kdc)
        self.assertEqual(error.exception.getErrorCode(), 91)
        self.assertEqual(len(kdc.requests), 4)

    def test_wrong_password_uses_protected_error(self):
        with self.assertRaises(KerberosError) as caught:
            self.get_tgt(FakeKDC(), password='wrong')
        self.assertEqual(caught.exception.getErrorCode(), 24)

    def test_tampered_replies(self):
        for kwargs, exception in [
                ({'bad_nonce': True}, ValueError),
                ({'bad_finished': True}, InvalidChecksum),
                ({'bad_challenge': True}, InvalidChecksum)]:
            with self.subTest(kwargs=kwargs), self.assertRaises(exception):
                self.get_tgt(FakeKDC(**kwargs))

    def test_no_silent_unarmored_reply(self):
        def unarmored(data, domain, host):
            reply = decode(FakeKDC()(data, domain, host), KRB_ERROR())
            methods = METHOD_DATA()
            methods[0] = FastContext.padata(19, b'')
            reply['e-data'] = encoder.encode(methods)
            return encoder.encode(reply)
        with self.assertRaises(ValueError):
            self.get_tgt(unarmored)

    def test_wrap_preserves_request(self):
        original = request()
        seq_set_iter(original, 'padata', [FastContext.padata(128, b'\x30\x05\xa0\x03\x01\x01\x00')])
        before = encoder.encode(original)
        wrapped = self.context().wrap(original)
        self.assertEqual(encoder.encode(original), before)
        self.assertLessEqual(int(wrapped['req-body']['nonce']), 0x7fffffff)

    def test_explicit_missing_cache_fails_before_network(self):
        with mock.patch('impacket.krb5.kerberosv5.sendReceive') as network, self.assertRaises(FileNotFoundError):
            getKerberosTGT(principal('user'), PASSWORD, REALM, b'', b'', armorCache='not-a-cache')
        network.assert_not_called()

    def test_policy_hint_without_armor(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=KerberosError(12)), \
             self.assertRaises(KerberosError) as error:
            getKerberosTGT(principal('user'), PASSWORD, REALM, b'', b'')
        self.assertIn(ARMOR_CACHE_ENV, str(error.exception))

    def test_armor_cache_selection(self):
        raw, cipher, reply_key, session_key = self.get_tgt(FakeKDC())
        cache = CCache()
        cache.fromTGT(raw, reply_key, session_key)
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'armor.ccache')
            cache.saveFile(path)
            self.assertEqual(FastContext.from_ccache('FILE:' + path, REALM, 17).key.enctype, 17)
            with self.assertRaises(ValueError):
                FastContext.from_ccache(path, 'OTHER.COM', 18)
            cache.credentials[0]['time']['endtime'] = 1
            cache.saveFile(path)
            with self.assertRaises(ValueError):
                FastContext.from_ccache(path, REALM, 18)

    def test_explicit_cache_overrides_environment(self):
        context = self.context()
        with mock.patch.dict(os.environ, {ARMOR_CACHE_ENV: 'environment.ccache'}), \
             mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=FakeKDC()), \
             mock.patch('impacket.krb5.kerberosv5.FastContext.from_ccache', return_value=context) as loader:
            getKerberosTGT(principal('user'), PASSWORD, REALM, b'', b'', armorCache='explicit.ccache')
        loader.assert_called_once_with('explicit.ccache', REALM, 18)

    def test_fragmented_and_closed_transport(self):
        sock = mock.Mock()
        sock.recv.side_effect = [b'\x00', b'\x00\x00', b'\x03']
        self.assertEqual(_recvExact(sock, 4), b'\x00\x00\x00\x03')
        sock.recv.side_effect = [b'\x00', b'']
        with self.assertRaises(EOFError):
            _recvExact(sock, 4)

    def test_tgs_retry_and_cache_roundtrip(self):
        raw, cipher, reply_key, session_key = self.get_tgt(FakeKDC())
        cache = CCache()
        cache.fromTGT(raw, reply_key, session_key)
        cached_tgt = cache.credentials[0].toTGT()['KDC_REP']
        kdc = FakeTGSKDC(session_key)
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=kdc):
            tgs, service_cipher, effective_key, service_key = getKerberosTGS(
                principal('cifs/server.example.com'), REALM, None, cached_tgt, cipher, session_key)
        self.assertEqual(kdc.calls, 2)
        self.assertEqual(tgs, kdc.raw_reply)
        self.assertEqual(service_cipher.enctype, 17)
        self.assertEqual(effective_key.enctype, 18)
        self.assertNotEqual(effective_key.contents, session_key.contents)
        cache = CCache()
        cache.fromTGS(tgs, effective_key, service_key)
        self.assertEqual(cache.credentials[0]['key']['keyvalue'], service_key.contents)

    def test_tgs_requires_strengthening_and_nonce(self):
        tgt, cipher, _, session_key = self.get_tgt(FakeKDC())
        for kwargs in ({'missing_strengthen': True}, {'bad_nonce': True}):
            kdc = FakeTGSKDC(session_key, **kwargs)
            with self.subTest(kwargs=kwargs), \
                 mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=kdc), \
                 self.assertRaises(ValueError):
                getKerberosTGS(principal('cifs/server.example.com'), REALM, None,
                               tgt, cipher, session_key, useFAST=True)

    def test_tgs_retries_once_after_closed_response(self):
        raw, cipher, reply_key, session_key = self.get_tgt(FakeKDC())
        cache = CCache()
        cache.fromTGT(raw, reply_key, session_key)
        tgt = cache.credentials[0].toTGT()['KDC_REP']
        kdc = FakeTGSKDC(session_key)
        calls = []

        def exchange(data, domain, host):
            calls.append(data)
            if len(calls) == 1:
                raise EOFError('KDC returned an empty reply')
            return kdc(data, domain, host)

        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=exchange):
            result = getKerberosTGS(principal('cifs/server.example.com'), REALM, None,
                                   tgt, cipher, session_key)
        self.assertEqual(result[0], kdc.raw_reply)
        self.assertEqual(len(calls), 2)

    def test_tgs_explicit_opt_out(self):
        tgt, cipher, _, session_key = self.get_tgt(FakeKDC())
        kdc = FakeTGSKDC(session_key)
        with mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=kdc), self.assertRaises(KerberosError):
            getKerberosTGS(principal('cifs/server.example.com'), REALM, None,
                           tgt, cipher, session_key, useFAST=False)
        self.assertEqual(kdc.calls, 1)

    def test_tgs_referral_keeps_fast_and_uses_new_session_key(self):
        tgt, cipher, _, session_key = self.get_tgt(FakeKDC())
        first = FakeTGSKDC(session_key, service_override='krbtgt/OTHER.COM')
        second = FakeTGSKDC(Key(17, bytes([6]) * 16))
        realms = []

        def exchange(data, realm, host):
            realms.append(realm)
            return (first if len(realms) == 1 else second)(data, realm, host)

        with mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=exchange):
            raw, cipher, reply_key, session_key = getKerberosTGS(
                principal('cifs/server.other.com'), REALM, None, tgt, cipher, session_key, useFAST=True)
        self.assertEqual(realms, [REALM, 'OTHER.COM'])
        self.assertEqual(raw, second.raw_reply)
        cache = CCache()
        cache.fromTGS(raw, reply_key, session_key)
        self.assertEqual(cache.credentials[0]['key']['keytype'], 17)
