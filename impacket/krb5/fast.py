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
import secrets
import time

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import (
    AP_REQ, Authenticator, EncryptedData, KDC_REQ_BODY, KRB_ERROR, METHOD_DATA,
    PA_DATA, PA_ENC_TS_ENC, PA_FX_FAST_REQUEST, PA_FX_FAST_REPLY,
    KrbFastReq, KrbFastResponse, Ticket as ASN1Ticket, seq_set, seq_set_iter,
)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, cf2, make_checksum, verify_checksum, _enctype_table
from impacket.krb5.types import KerberosTime, Ticket

ARMOR_CACHE_ENV = 'IMPACKET_KRB5_ARMOR_CCACHE'
FAST_REQ_CHECKSUM = 50
FAST_ENC = 51
FAST_REP = 52
FAST_FINISHED = 53
CHALLENGE_CLIENT = 54
CHALLENGE_KDC = 55


def decode(data, schema):
    value, trailing = decoder.decode(data, asn1Spec=schema)
    if trailing:
        raise ValueError('Trailing data in Kerberos FAST message')
    return value


def get_padata(methods, kind):
    if not methods.hasValue():
        raise ValueError('Missing FAST padata type %d' % kind)
    matches = [method['padata-value'].asOctets() for method in methods
               if int(method['padata-type']) == kind]
    if len(matches) != 1:
        raise ValueError('Missing or duplicate FAST padata type %d' % kind)
    return matches[0]


def _copy_sequence(destination, source):
    for field in source.componentType.namedTypes:
        value = source[field.name]
        if value.hasValue():
            destination[field.name] = value
    return destination


class FastContext:
    def __init__(self, key, armor=None):
        self.key = key
        self.armor = armor
        self.cookies = []
        self.response = None
        self.nonce = None
        self.tgs = False

    @staticmethod
    def checksum_type(enctype):
        types = {17: 15, 18: 16, 23: -138}
        if enctype not in types:
            raise ValueError('FAST requires an AES or RC4 key')
        return types[enctype]

    @classmethod
    def from_ccache(cls, path, realm, enctype):
        path = os.fsdecode(path)
        if path.startswith('FILE:'):
            path = path[5:]
        if not path:
            raise ValueError('FAST armor cache path is empty')
        cache = CCache.loadFile(path)
        now = time.time()
        for credential in cache.credentials:
            server = credential['server'].toPrincipal()
            times = credential['time']
            if (len(server.components) != 2 or server.components[0].lower() != 'krbtgt' or
                    server.components[1].upper() != realm.upper() or
                    times['endtime'] <= now or times['starttime'] > now):
                continue
            if credential['key']['keytype'] not in (17, 18, 23):
                continue
            session_key = Key(credential['key']['keytype'], credential['key']['keyvalue'])
            if not any(session_key.contents):
                continue
            ticket = decode(credential.ticket['data'], ASN1Ticket())
            ticket_names = tuple(str(part) for part in ticket['sname']['name-string'])
            if tuple(server.components) != ticket_names:
                raise ValueError('Armor cache principal does not match its ticket')
            return cls.for_as(ticket, credential['client'].toPrincipal(), session_key, enctype)
        raise ValueError('No unexpired armor TGT for %s in %s' % (realm, path))

    @classmethod
    def for_as(cls, ticket, client, session_key, enctype):
        cls.checksum_type(enctype)
        subkey = _enctype_table[enctype].random_to_key(os.urandom(_enctype_table[enctype].seedsize))
        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = client.realm
        seq_set(authenticator, 'cname', client.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator['ctime'] = KerberosTime.to_asn1(now)
        authenticator['cusec'] = now.microsecond
        authenticator['subkey'] = noValue
        authenticator['subkey']['keytype'] = subkey.enctype
        authenticator['subkey']['keyvalue'] = subkey.contents

        ap_req = AP_REQ()
        ap_req['pvno'] = 5
        ap_req['msg-type'] = 14
        ap_req['ap-options'] = constants.encodeFlags([])
        typed_ticket = Ticket()
        typed_ticket.from_asn1(ticket)
        seq_set(ap_req, 'ticket', typed_ticket.to_asn1)
        ap_req['authenticator'] = noValue
        ap_req['authenticator']['etype'] = session_key.enctype
        ap_req['authenticator']['cipher'] = _enctype_table[session_key.enctype].encrypt(
            session_key, 11, encoder.encode(authenticator), None)
        armor_key = cf2(enctype, subkey, session_key, b'subkeyarmor', b'ticketarmor')
        return cls(armor_key, encoder.encode(ap_req))

    @classmethod
    def for_tgs(cls, ap_req, authenticator, session_key):
        cls.checksum_type(session_key.enctype)
        cipher = _enctype_table[session_key.enctype]
        subkey = cipher.random_to_key(os.urandom(cipher.seedsize))
        key = cf2(subkey.enctype, subkey, session_key, b'subkeyarmor', b'ticketarmor')
        context = cls(key)
        context.tgs = True
        context.subkey = subkey
        context.ticket_session_key = session_key
        context.ap_req = decode(encoder.encode(ap_req), AP_REQ())
        context.authenticator = decode(encoder.encode(authenticator), Authenticator())
        context.authenticator['subkey'] = noValue
        context.authenticator['subkey']['keytype'] = subkey.enctype
        context.authenticator['subkey']['keyvalue'] = subkey.contents
        return context

    def wrap(self, request, key=None):
        if self.tgs != (int(request['msg-type']) == 12):
            raise ValueError('FAST context does not match the request type')
        wrapped = decode(encoder.encode(request), request.__class__())
        self.response = None
        # Windows FAST uses signed-range nonces.
        self.nonce = secrets.randbits(31)
        wrapped['req-body']['nonce'] = self.nonce
        inner = KrbFastReq()
        inner['fast-options'] = constants.encodeFlags([])
        _copy_sequence(seq_set(inner, 'req-body'), wrapped['req-body'])
        methods = [method for method in request['padata']
                   if int(method['padata-type']) not in (1, 2, 133, 136)]
        if key is not None and not self.tgs:
            methods.append(self.encrypted_challenge(key))
        methods.extend(self.cookies)
        seq_set_iter(inner, 'padata', methods)

        choice = PA_FX_FAST_REQUEST()
        armored = seq_set(choice, 'armored-data')
        if self.armor is not None:
            armored['armor'] = noValue
            armored['armor']['armor-type'] = 1
            armored['armor']['armor-value'] = self.armor
        checksum_data = encoder.encode(_copy_sequence(KDC_REQ_BODY(), wrapped['req-body']))
        if self.tgs:
            # The ordinary checksum covers the body; FAST's checksum covers the AP-REQ.
            session_key = self.ticket_session_key
            checksum_type = self.checksum_type(session_key.enctype)
            self.authenticator['cksum'] = noValue
            self.authenticator['cksum']['cksumtype'] = checksum_type
            self.authenticator['cksum']['checksum'] = make_checksum(checksum_type, session_key, 6, checksum_data)
            self.ap_req['authenticator']['cipher'] = _enctype_table[session_key.enctype].encrypt(
                session_key, 7, encoder.encode(self.authenticator), None)
            checksum_data = encoder.encode(self.ap_req)
        armored['req-checksum'] = noValue
        armored['req-checksum']['cksumtype'] = self.checksum_type(self.key.enctype)
        armored['req-checksum']['checksum'] = make_checksum(
            self.checksum_type(self.key.enctype), self.key, FAST_REQ_CHECKSUM, checksum_data)
        armored['enc-fast-req'] = noValue
        armored['enc-fast-req']['etype'] = self.key.enctype
        armored['enc-fast-req']['cipher'] = _enctype_table[self.key.enctype].encrypt(
            self.key, FAST_ENC, encoder.encode(inner), None)
        wrapped['padata'].clear()
        outer = [self.padata(1, checksum_data)] if self.tgs else []
        outer.append(self.padata(136, encoder.encode(choice)))
        seq_set_iter(wrapped, 'padata', outer)
        return wrapped

    @staticmethod
    def padata(kind, value):
        method = PA_DATA()
        method['padata-type'] = kind
        method['padata-value'] = value
        return method

    def encrypted_challenge(self, key):
        timestamp = PA_ENC_TS_ENC()
        now = datetime.datetime.now(datetime.timezone.utc)
        timestamp['patimestamp'] = KerberosTime.to_asn1(now)
        timestamp['pausec'] = now.microsecond
        challenge_key = cf2(self.key.enctype, self.key, key, b'clientchallengearmor', b'challengelongterm')
        encrypted = EncryptedData()
        encrypted['etype'] = challenge_key.enctype
        encrypted['cipher'] = _enctype_table[challenge_key.enctype].encrypt(
            challenge_key, CHALLENGE_CLIENT, encoder.encode(timestamp), None)
        return self.padata(138, encoder.encode(encrypted))

    def unwrap(self, reply):
        is_error = int(reply['msg-type']) == 30
        methods = decode(reply['e-data'].asOctets(), METHOD_DATA()) if is_error else reply['padata']
        choice = decode(get_padata(methods, 136), PA_FX_FAST_REPLY())
        encrypted = choice['armored-data']['enc-fast-rep']
        if int(encrypted['etype']) != self.key.enctype:
            raise ValueError('FAST reply enctype does not match the armor key')
        response = decode(_enctype_table[self.key.enctype].decrypt(
            self.key, FAST_REP, encrypted['cipher'].asOctets()), KrbFastResponse())
        if int(response['nonce']) != self.nonce:
            raise ValueError('FAST reply nonce does not match the request')
        if is_error:
            if response['finished'].hasValue() or response['strengthen-key'].hasValue():
                raise ValueError('Unexpected finished field or strengthen key in FAST error')
        else:
            if not response['finished'].hasValue():
                raise ValueError('FAST reply is missing the finished field')
            if self.tgs and not response['strengthen-key'].hasValue():
                raise ValueError('FAST TGS reply is missing the strengthen key')
            finished = response['finished']
            checksum = finished['ticket-checksum']
            if int(checksum['cksumtype']) != self.checksum_type(self.key.enctype):
                raise ValueError('Unexpected FAST ticket checksum type')
            verify_checksum(int(checksum['cksumtype']), self.key, FAST_FINISHED,
                            encoder.encode(reply['ticket'].clone(tagSet=ASN1Ticket.tagSet, cloneValueFlag=True)),
                            checksum['checksum'].asOctets())
            if (str(reply['crealm']) != str(finished['crealm']) or
                    int(reply['cname']['name-type']) != int(finished['cname']['name-type']) or
                    tuple(map(str, reply['cname']['name-string'])) != tuple(map(str, finished['cname']['name-string']))):
                raise ValueError('FAST reply identity does not match the authenticated identity')
        self.response = response
        self.cookies = [method for method in response['padata'] if int(method['padata-type']) == 133]
        return response

    def get_error(self):
        error = decode(get_padata(self.response['padata'], 137), KRB_ERROR())
        if error['e-data'].hasValue():
            raise ValueError('PA-FX-ERROR must not contain e-data')
        return error

    def reply_key(self, key, challenge=False):
        strengthen = self.response['strengthen-key']
        if challenge:
            if not strengthen.hasValue():
                raise ValueError('Encrypted-challenge reply is missing the strengthen key')
            encrypted = decode(get_padata(self.response['padata'], 138), EncryptedData())
            challenge_key = cf2(self.key.enctype, self.key, key, b'kdcchallengearmor', b'challengelongterm')
            if int(encrypted['etype']) != challenge_key.enctype:
                raise ValueError('Unexpected KDC challenge enctype')
            decode(_enctype_table[challenge_key.enctype].decrypt(
                challenge_key, CHALLENGE_KDC, encrypted['cipher'].asOctets()), PA_ENC_TS_ENC())
        if not strengthen.hasValue():
            return key
        if int(strengthen['keytype']) != key.enctype:
            raise ValueError('FAST strengthen key enctype does not match the reply key')
        strengthen_key = Key(key.enctype, strengthen['keyvalue'].asOctets())
        return cf2(key.enctype, strengthen_key, key, b'strengthenkey', b'replykey')
