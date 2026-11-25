"""Mock ResolverRpc.Open for the escrow layer: sign-address request/response (+ refresh), RFQ -> update_quote,
then OrderUpdated, ExecutionUpdated, OrderClosed. Local test only - NOT the real STON.fi server."""
import sys, time, json, concurrent.futures as cf
sys.path.insert(0, __file__.rsplit('/',1)[0] + '/gen')
import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from stonfi.omni.v1beta8.resolver import service_pb2_grpc, event_pb2
res = {'sign_requests': []}
mock_key = Ed25519PrivateKey.generate()
RES = 'EQ_TEST_RESOLVER'; CONTRACT = 'EQ_TEST_PROTOCOL'; ESCROW = 'EQ_TEST_ESCROW'

def build_quote(rfq):
    q = event_pb2.QuoteRequestedEvent  # noqa
    from stonfi.omni.v1beta8.types import quote_pb2
    qt = quote_pb2.Quote(rfq_id=rfq, quote_id='quote-1', resolver_id=RES, resolver_name='WebMesh',
                         input_units='1000000000', output_units='997000000', integrator_fee_units='0',
                         protocol_fee_units='997000', quote_timestamp=int(time.time()))
    qt.input_asset.ton.native.SetInParent(); qt.output_asset.ton.jetton = 'EQ_TEST_JETTON'
    o = qt.order
    o.src_protocol_contract_address.ton = CONTRACT; o.src_initial_resolver_address.ton = RES
    o.src_wrapped_native_token_address.ton = 'EQ_WTON'
    o.resolver_sends_units = '997997000'; o.trade_start_deadline = int(time.time()) + 300
    o.exclusivity_timeout = 120; o.protocol_fee_pips = 1000
    return qt

def sign_event(req):
    ev = event_pb2.ResolverAddressSignedEvent()
    ev.resolver_address.CopyFrom(req.sign_resolver_address.resolver_address)
    ev.protocol_contract_address.CopyFrom(req.sign_resolver_address.protocol_contract_address)
    ev.public_key = mock_key.public_key().public_bytes_raw()
    ev.signature = mock_key.sign(b'x' * 8)
    ev.validity_deadline = int(time.time()) + 70
    return event_pb2.ResolverEvent(reply_to=req.seqno, resolver_address_signed=ev)

class Svc(service_pb2_grpc.ResolverRpcServicer):
    def Open(self, it, ctx):
        first = next(it)
        yield event_pb2.ResolverEvent(reply_to=first.seqno, connected=event_pb2.ConnectedEvent())
        m = next(it)                                  # client's SignResolverAddress
        r = m.sign_resolver_address
        res['sign_requests'].append(dict(resolver=r.resolver_address.ton, contract=r.protocol_contract_address.ton, seqno=m.seqno))
        yield sign_event(m)
        ev = event_pb2.ResolverEvent(seqno=1, quote_requested=event_pb2.QuoteRequestedEvent(
            rfq_id='rfq-1', resolver_receives_units='1000000000', request_timestamp=int(time.time())))
        ev.quote_requested.quote_request.input_asset.ton.native.SetInParent()
        ev.quote_requested.quote_request.output_asset.ton.jetton = 'EQ_TEST_JETTON'
        yield ev
        u = next(it).update_quote
        res['update_quote'] = dict(rfq=u.rfq_id, sends=u.quote.resolver_sends_units)
        qt = build_quote('rfq-1')
        yield event_pb2.ResolverEvent(seqno=2, quote_accepted=event_pb2.QuoteAcceptedEvent(rfq_id='rfq-1', quote_id='quote-1'))
        ou = event_pb2.OrderUpdatedEvent(remaining_input_units='1000000000', remaining_secrets=3,
                                         cancellation_available_timestamp=int(time.time()) + 400,
                                         serialized_order_details=b'\x0a\x07details',)
        ou.quote.CopyFrom(qt); ou.exclusive_resolver_address.ton = RES; ou.escrow_address.ton = ESCROW
        ou.dst_position_params.ton.condition_code_cell = b'\xb5\xee\x9c\x72' * 8
        yield event_pb2.ResolverEvent(seqno=3, order_updated=ou)
        ex = event_pb2.ExecutionUpdatedEvent(secret=b'S' * 32)
        ex.quote.CopyFrom(qt)
        ex.execution.index = 0; ex.execution.input_units = '1000000000'; ex.execution.output_units = '997000000'
        ex.execution.resolver_sends_units = '997997000'; ex.execution.secret_hash = b'H' * 32
        ex.execution.resolver_id = RES; ex.execution.resolver_name = 'WebMesh'
        ex.execution.input_position_address.ton = ESCROW; ex.execution.input_position_phase = 1
        ex.execution.input_position_phase_timestamps.private_rollback_available_timestamp = 1795470000
        ex.execution.src_resolver_address.ton = RES
        ex.execution.output_position_address.ton = 'EQ_OUT_POS'; ex.execution.output_position_phase = 0
        ex.escrow_address.ton = ESCROW
        yield event_pb2.ResolverEvent(seqno=4, execution_updated=ex)
        yield event_pb2.ResolverEvent(seqno=5, order_closed=event_pb2.OrderClosedEvent(quote_id='quote-1'))
        m = next(it)                                  # refresh request (~10 s later)
        r = m.sign_resolver_address
        res['sign_requests'].append(dict(resolver=r.resolver_address.ton, contract=r.protocol_contract_address.ton, seqno=m.seqno))
        yield sign_event(m)
        time.sleep(0.3)
        print(json.dumps(res, indent=1), flush=True)

s = grpc.server(cf.ThreadPoolExecutor(4))
service_pb2_grpc.add_ResolverRpcServicer_to_server(Svc(), s)
s.add_insecure_port('127.0.0.1:50552'); s.start(); print('mock up', flush=True); s.wait_for_termination()
