from typing import Dict, Any

# module-level
def handle_tlsrec_split(engine, packet, w, params, payload) -> bool:
    sp = int(params.get("split_pos", 5))
    if params.get("tcp_segmentation", True):
        return engine._send_tlsrec_split_segments(packet, w, payload, sp, delay_ms=int(params.get("delay_ms", 2)))
    else:
        mp = engine.techniques.apply_tlsrec_split(payload, sp)
        return engine._send_modified_packet(packet, w, mp)

def handle_wssize_limit(engine, packet, w, params, payload) -> bool:
    segments = engine.techniques.apply_wssize_limit(payload, params.get("window_size", 2))
    return engine._send_segments_with_window(packet, w, segments)

EXEC_HANDLERS = {
    "tlsrec_split": handle_tlsrec_split,
    "wssize_limit": handle_wssize_limit,
}
