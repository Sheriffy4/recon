
# Windows Engine Regression Analysis Report

## Summary
Analysis of regression between windows_engine.py and new_windows_engine.py

## Issues Found (5 total):
1. Removed imports: {'import string'}
2. @trace_calls decorator: old=False, new=True
3. CRITICAL: new_windows_engine.py calls send_tcp_segments_async which may not exist
4. CRITICAL: send_tcp_segments_async method missing from PacketSender
5. _active_flows logic differs between versions

## Key Findings:

### 1. Missing Async Method (CRITICAL)
- new_windows_engine.py calls `send_tcp_segments_async()` 
- This method does NOT exist in PacketSender class
- Causes fallback to regular method, but may introduce timing issues

### 2. Trace Decorator Addition
- new_windows_engine.py adds @trace_calls decorator to apply_bypass
- This adds logging overhead that could affect performance
- May interfere with packet injection timing

### 3. Shim Layer Changes
- Both versions use PacketSender integration
- New version attempts async sending which fails
- Fallback mechanism may not work correctly

## Recommended Fixes:

1. **Remove async method call** - Use only send_tcp_segments()
2. **Remove @trace_calls decorator** - Eliminate logging overhead  
3. **Verify shim layer integrity** - Ensure all calls go through correctly
4. **Test flow handling** - Verify _active_flows logic works correctly

## Next Steps:
1. Apply fixes to new_windows_engine.py
2. Run unit tests to verify fixes
3. Compare PCAP output with working version
4. Measure success rates after fixes
