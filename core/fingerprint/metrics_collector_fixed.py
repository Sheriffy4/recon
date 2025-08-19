    async def collect_metrics(self, target: str, port: int, **kwargs) -> Dict[str, Any]:
        """Collect comprehensive timing metrics"""
        timing_data = []
        connection_times = []
        first_byte_times = []
        max_retries = 3  # Add retries for resilience
        retry_delay = 1.0  # Delay between retries
        
        for i in range(self.samples):
            success = False
            last_error = None
            
            # Try connection with retries
            for retry in range(max_retries):
                try:
                    start_time = time.perf_counter()
                    
                    # Attempt TCP connection with progressive timeouts
                    connection_start = time.perf_counter()
                    adjusted_timeout = self.timeout * (1 + retry * 0.5)
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=adjusted_timeout
                    )
                    connection_time = (time.perf_counter() - connection_start) * 1000
                    connection_times.append(connection_time)
                    
                    # Send minimal HTTP request to measure first byte time
                    first_byte_start = time.perf_counter()
                    writer.write(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                    await writer.drain()
                    
                    # Read first byte with adjusted timeout
                    first_byte = await asyncio.wait_for(
                        reader.read(1),
                        timeout=adjusted_timeout
                    )
                    first_byte_time = (time.perf_counter() - first_byte_start) * 1000
                    first_byte_times.append(first_byte_time)
                    
                    total_time = (time.perf_counter() - start_time) * 1000
                    timing_data.append(total_time)
                    
                    writer.close()
                    await writer.wait_closed()
                    
                    success = True
                    break  # Break retry loop on success
                
                except (asyncio.TimeoutError, ConnectionError, OSError) as e:
                    last_error = e
                    self.logger.warning(f"Attempt {retry + 1}/{max_retries} failed: {e}")
                    if retry < max_retries - 1:
                        await asyncio.sleep(retry_delay * (retry + 1))
                    continue
            
            if not success:
                self.logger.error(f"All attempts failed for measurement {i+1}/{self.samples}: {last_error}")
                timing_data.append(self.timeout * 1000)  # Record timeout as max time
            
            # Add jitter between samples to avoid overwhelming the target
            if i < self.samples - 1:
                await asyncio.sleep(0.1 + random.uniform(0, 0.1))
        
        # Calculate statistics
        if timing_data:
            latency_ms = statistics.mean(timing_data)
            jitter_ms = statistics.stdev(timing_data) if len(timing_data) > 1 else 0.0
        else:
            latency_ms = jitter_ms = 0.0
        
        avg_connection_time = statistics.mean(connection_times) if connection_times else 0.0
        avg_first_byte_time = statistics.mean(first_byte_times) if first_byte_times else 0.0
        
        # Store in history for trend analysis
        self.timing_history.append({
            'timestamp': time.time(),
            'latency_ms': latency_ms,
            'jitter_ms': jitter_ms
        })
        
        return {
            'latency_ms': latency_ms,
            'jitter_ms': jitter_ms,
            'packet_timing': timing_data,
            'connection_time_ms': avg_connection_time,
            'first_byte_time_ms': avg_first_byte_time,
            'total_time_ms': statistics.mean(timing_data) if timing_data else 0.0,
            'timeout_occurred': any(t >= self.timeout * 1000 for t in timing_data),
            'retransmission_count': 0,  # Would need packet capture for accurate count
            'samples_collected': len(timing_data),
            'success_rate': len([t for t in timing_data if t < self.timeout * 1000]) / self.samples if self.samples > 0 else 0.0
        }
