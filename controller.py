import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

REST_API_NAME = "zt_firewall_api"
URL_BLOCK = "/firewall/block"
URL_ALLOW = "/firewall/allow"
URL_STATUS = "/firewall/status"

class ZeroTrustDDoSFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(ZeroTrustDDoSFirewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.blocked_ips = set()
        self.prev_flow_stats = {}
        self.ATTACK_THRESHOLD = 500
        wsgi = kwargs["wsgi"]
        wsgi.register(FirewallController, {REST_API_NAME: self})
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Switch connected: Active DDoS Defense Ready.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, idle_timeout=idle_timeout, instructions=inst)
        datapath.send_msg(mod)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(1)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser

        for stat in [flow for flow in body if flow.priority == 10]:
            match = stat.match
            if "ipv4_src" in match:
                src_ip = match["ipv4_src"]
                flow_key = (datapath.id, src_ip)
                packet_count = stat.packet_count
                
                if flow_key in self.prev_flow_stats:
                    prev_packets = self.prev_flow_stats[flow_key]
                    rate = packet_count - prev_packets
                    if rate > self.ATTACK_THRESHOLD and src_ip not in self.blocked_ips:
                        self.logger.error(f"[DDoS SENTINEL] Flood Attack Detected from {src_ip}! Packet Rate: {rate} pkt/s. Auto-Quarantining...")
                        self.blocked_ips.add(src_ip)
                        drop_src = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
                        drop_dst = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=src_ip)
                        self.add_flow(datapath, 300, drop_src, actions=[], idle_timeout=120)
                        self.add_flow(datapath, 300, drop_dst, actions=[], idle_timeout=120)
                self.prev_flow_stats[flow_key] = packet_count

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            if src_ip in self.blocked_ips or dst_ip in self.blocked_ips:
                drop_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
                self.add_flow(datapath, 200, drop_match, actions=[], idle_timeout=30)
                return

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
                self.add_flow(datapath, 10, match, actions, idle_timeout=15)
                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return

        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

class FirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FirewallController, self).__init__(req, link, data, **config)
        self.app = data[REST_API_NAME]

    def _cors_response(self, body_data, status=200):
        res_bytes = json.dumps(body_data).encode("utf-8")
        res = Response(status=status, content_type="application/json", body=res_bytes)
        res.headers.add("Access-Control-Allow-Origin", "*")
        res.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        res.headers.add("Access-Control-Allow-Headers", "Content-Type")
        return res

    @route("firewall", URL_STATUS, methods=["GET", "OPTIONS"])
    def get_status(self, req, **kwargs):
        if req.method == "OPTIONS":
            return self._cors_response({})
        return self._cors_response({"blocked_ips": list(self.app.blocked_ips)})

    @route("firewall", URL_BLOCK, methods=["POST", "OPTIONS"])
    def block_ip(self, req, **kwargs):
        if req.method == "OPTIONS":
            return self._cors_response({})
        try:
            req_data = req.json_body
            ip = req_data.get("ip")
            if ip:
                self.app.blocked_ips.add(ip)
                return self._cors_response({"message": f"IP {ip} blocked successfully."})
        except Exception as e:
            return self._cors_response({"error": str(e)}, status=400)

    @route("firewall", URL_ALLOW, methods=["POST", "OPTIONS"])
    def allow_ip(self, req, **kwargs):
        if req.method == "OPTIONS":
            return self._cors_response({})
        try:
            req_data = req.json_body
            ip = req_data.get("ip")
            if ip in self.app.blocked_ips:
                self.app.blocked_ips.remove(ip)
                return self._cors_response({"message": f"IP {ip} unblocked successfully."})
            return self._cors_response({"message": f"IP {ip} was not in blocklist."})
        except Exception as e:
            return self._cors_response({"error": str(e)}, status=400)
