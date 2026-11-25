"""Local mock of ResolverRpc.Open for testing the C client (NOT the real STON.fi server).
Verifies the Ed25519 signature, sends connected, then one quote_requested, then checks update_quote."""
import sys, time, json, concurrent.futures as cf
sys.path.insert(0, __file__.rsplit('/',1)[0] + '/gen')
import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from stonfi.omni.v1beta8.resolver import service_pb2_grpc, event_pb2, request_pb2
from stonfi.omni.v1beta8.types import quote_pb2

result = {}
class Svc(service_pb2_grpc.ResolverRpcServicer):
    def Open(self, it, ctx):
        first = next(it)
        c = first.connect
        try:
            Ed25519PublicKey.from_public_bytes(c.public_key).verify(c.signature, c.serialized_authentication_payload)
            result['sig_ok'] = True
        except Exception as e:
            result['sig_ok'] = False; result['err'] = repr(e); result['pk'] = c.public_key.hex(); result['siglen']=len(c.signature)
        ap = request_pb2.AuthenticationPayload(); ap.ParseFromString(c.serialized_authentication_payload)
        result['stake'] = ap.stake_address; result['ts_drift_ms'] = abs(int(time.time()*1000) - ap.connect_timestamp)
        result['seqno'] = first.seqno
        yield event_pb2.ResolverEvent(reply_to=first.seqno, connected=event_pb2.ConnectedEvent())
        for amt_field, amt in (('resolver_receives_units','1000000000'), ('resolver_sends_units','500000000')):
            ev = event_pb2.ResolverEvent(seqno=1, quote_requested=event_pb2.QuoteRequestedEvent(
                rfq_id='rfq-'+amt_field, **{amt_field: amt}, request_timestamp=int(time.time()),
                protocol_params=event_pb2.ProtocolParams(quote_validity_timeout=45)))
            qr = ev.quote_requested.quote_request
            qr.input_asset.ton.native.SetInParent()
            qr.output_asset.ton.jetton = 'EQDtFpEwcFAEcRe5mLVh2N6C0x-_hJEM7W61_JLnSF74p4q2'
            yield ev
            msg = next(it)
            u = msg.update_quote
            result[amt_field] = dict(rfq=u.rfq_id, recv=u.quote.resolver_receives_units, sends=u.quote.resolver_sends_units,
                src=u.quote.resolver_src_address.ton, dst=u.quote.resolver_dst_address.ton,
                deadline_in_s=u.quote.trade_start_deadline - int(time.time()), seqno=msg.seqno)
        yield event_pb2.ResolverEvent(seqno=2, quote_accepted=event_pb2.QuoteAcceptedEvent(rfq_id='rfq-resolver_receives_units', quote_id='q-1'))
        yield event_pb2.ResolverEvent(seqno=3, keep_alive=event_pb2.KeepAlive()) if hasattr(event_pb2,'KeepAlive') else event_pb2.ResolverEvent(seqno=3)
        time.sleep(0.5)
        print(json.dumps(result, indent=1), flush=True)

s = grpc.server(cf.ThreadPoolExecutor(4))
service_pb2_grpc.add_ResolverRpcServicer_to_server(Svc(), s)
s.add_insecure_port('127.0.0.1:50551'); s.start(); print('mock up', flush=True); s.wait_for_termination()
