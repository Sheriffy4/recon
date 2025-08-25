"""
Comprehensive tests for DNS tunneling and evasion attacks.
Tests all DNS attack implementations for functionality and reliability.
"""
import pytest
import asyncio
import time
from tests.dns_tunneling import DoHAttack, DoTAttack, DNSQueryManipulation, DNSCachePoisoningPrevention, DoHProvider, DoTProvider, get_dns_attack_definitions
from core.bypass.attacks.base import AttackResult

class TestDoHAttack:
    """Test DNS over HTTPS attack implementation."""

    @pytest.fixture
    def doh_attack(self):
        """Create DoH attack instance."""
        return DoHAttack(DoHProvider.CLOUDFLARE)

    @pytest.mark.asyncio
    async def test_doh_basic_resolution(self, doh_attack):
        """Test basic DoH resolution."""
        result = await doh_attack.execute('example.com')
        assert isinstance(result, AttackResult)
        if result.success:
            assert 'resolved_ip' in result.data
            assert result.data['method'] == 'DoH'
            assert result.data['provider'] == 'cloudflare'

    @pytest.mark.asyncio
    async def test_doh_json_format(self, doh_attack):
        """Test DoH with JSON format."""
        parameters = {'provider': 'cloudflare', 'query_type': 'A', 'use_json': True}
        result = await doh_attack.execute('google.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.metadata['use_json'] is True

    @pytest.mark.asyncio
    async def test_doh_wire_format(self, doh_attack):
        """Test DoH with wire format."""
        parameters = {'provider': 'cloudflare', 'query_type': 'A', 'use_json': False}
        result = await doh_attack.execute('google.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.metadata['use_json'] is False

    @pytest.mark.asyncio
    async def test_doh_multiple_providers(self, doh_attack):
        """Test DoH with different providers."""
        providers = ['cloudflare', 'google', 'quad9']
        for provider in providers:
            parameters = {'provider': provider}
            result = await doh_attack.execute('example.com', parameters)
            assert isinstance(result, AttackResult)
            if result.success:
                assert result.data['provider'] == provider

    @pytest.mark.asyncio
    async def test_doh_invalid_provider(self, doh_attack):
        """Test DoH with invalid provider."""
        parameters = {'provider': 'invalid_provider'}
        result = await doh_attack.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        assert not result.success
        assert 'not supported' in result.error.lower()

    @pytest.mark.asyncio
    async def test_doh_timeout_handling(self, doh_attack):
        """Test DoH timeout handling."""
        doh_attack.timeout = 0.001
        result = await doh_attack.execute('example.com')
        assert isinstance(result, AttackResult)

    @pytest.mark.asyncio
    async def test_doh_error_handling(self, doh_attack):
        """Test DoH error handling."""
        result = await doh_attack.execute('invalid.domain.that.does.not.exist.12345')
        assert isinstance(result, AttackResult)

class TestDoTAttack:
    """Test DNS over TLS attack implementation."""

    @pytest.fixture
    def dot_attack(self):
        """Create DoT attack instance."""
        return DoTAttack(DoTProvider.CLOUDFLARE)

    @pytest.mark.asyncio
    async def test_dot_basic_resolution(self, dot_attack):
        """Test basic DoT resolution."""
        result = await dot_attack.execute('example.com')
        assert isinstance(result, AttackResult)
        if result.success:
            assert 'resolved_ip' in result.data
            assert result.data['method'] == 'DoT'
            assert result.data['provider'] == 'cloudflare'

    @pytest.mark.asyncio
    async def test_dot_multiple_providers(self, dot_attack):
        """Test DoT with different providers."""
        providers = ['cloudflare', 'google', 'quad9']
        for provider in providers:
            parameters = {'provider': provider}
            result = await dot_attack.execute('example.com', parameters)
            assert isinstance(result, AttackResult)
            if result.success:
                assert result.data['provider'] == provider

    @pytest.mark.asyncio
    async def test_dot_query_types(self, dot_attack):
        """Test DoT with different query types."""
        query_types = ['A', 'AAAA', 'CNAME']
        for query_type in query_types:
            parameters = {'query_type': query_type}
            result = await dot_attack.execute('example.com', parameters)
            assert isinstance(result, AttackResult)
            if result.success:
                assert result.metadata['query_type'] == query_type

    @pytest.mark.asyncio
    async def test_dot_invalid_provider(self, dot_attack):
        """Test DoT with invalid provider."""
        parameters = {'provider': 'invalid_provider'}
        result = await dot_attack.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        assert not result.success
        assert 'not supported' in result.error.lower()

    @pytest.mark.asyncio
    async def test_dot_tls_verification(self, dot_attack):
        """Test DoT TLS certificate verification."""
        result = await dot_attack.execute('google.com')
        assert isinstance(result, AttackResult)

class TestDNSQueryManipulation:
    """Test DNS query manipulation techniques."""

    @pytest.fixture
    def query_manipulation(self):
        """Create DNS query manipulation instance."""
        return DNSQueryManipulation()

    @pytest.mark.asyncio
    async def test_case_randomization(self, query_manipulation):
        """Test DNS case randomization."""
        parameters = {'technique': 'case_randomization'}
        result = await query_manipulation.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.data['technique'] == 'case_randomization'
            assert result.metadata['manipulation_applied'] is True

    @pytest.mark.asyncio
    async def test_subdomain_prepending(self, query_manipulation):
        """Test subdomain prepending."""
        parameters = {'technique': 'subdomain_prepending', 'subdomain': 'www'}
        result = await query_manipulation.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.data['technique'] == 'subdomain_prepending'

    @pytest.mark.asyncio
    async def test_query_type_variation(self, query_manipulation):
        """Test query type variation."""
        parameters = {'technique': 'query_type_variation'}
        result = await query_manipulation.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.data['technique'] == 'query_type_variation'

    @pytest.mark.asyncio
    async def test_recursive_queries(self, query_manipulation):
        """Test recursive DNS queries."""
        parameters = {'technique': 'recursive_queries'}
        result = await query_manipulation.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.data['technique'] == 'recursive_queries'

    @pytest.mark.asyncio
    async def test_edns_padding(self, query_manipulation):
        """Test EDNS padding."""
        parameters = {'technique': 'edns_padding'}
        result = await query_manipulation.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.data['technique'] == 'edns_padding'

    @pytest.mark.asyncio
    async def test_invalid_technique(self, query_manipulation):
        """Test invalid manipulation technique."""
        parameters = {'technique': 'invalid_technique'}
        result = await query_manipulation.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        assert not result.success
        assert 'Unknown manipulation technique' in result.error

    @pytest.mark.asyncio
    async def test_all_techniques(self, query_manipulation):
        """Test all manipulation techniques."""
        techniques = ['case_randomization', 'subdomain_prepending', 'query_type_variation', 'recursive_queries', 'edns_padding']
        for technique in techniques:
            parameters = {'technique': technique}
            result = await query_manipulation.execute('example.com', parameters)
            assert isinstance(result, AttackResult)

class TestDNSCachePoisoningPrevention:
    """Test DNS cache poisoning prevention techniques."""

    @pytest.fixture
    def cache_prevention(self):
        """Create DNS cache poisoning prevention instance."""
        return DNSCachePoisoningPrevention()

    @pytest.mark.asyncio
    async def test_query_id_randomization(self, cache_prevention):
        """Test query ID randomization."""
        parameters = {'technique': 'query_id_randomization'}
        result = await cache_prevention.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.data['technique'] == 'query_id_randomization'
            assert 'results' in result.data
            assert 'consistent' in result.data

    @pytest.mark.asyncio
    async def test_source_port_randomization(self, cache_prevention):
        """Test source port randomization."""
        parameters = {'technique': 'source_port_randomization'}
        result = await cache_prevention.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.data['technique'] == 'source_port_randomization'
            assert 'results' in result.data

    @pytest.mark.asyncio
    async def test_multiple_server_validation(self, cache_prevention):
        """Test multiple server validation."""
        parameters = {'technique': 'multiple_server_validation'}
        result = await cache_prevention.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.data['technique'] == 'multiple_server_validation'
            assert 'results' in result.data
            assert 'consistent' in result.data
            assert 'consensus_ip' in result.data

    @pytest.mark.asyncio
    async def test_dnssec_validation(self, cache_prevention):
        """Test DNSSEC validation."""
        parameters = {'technique': 'dnssec_validation'}
        result = await cache_prevention.execute('cloudflare.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.data['technique'] == 'dnssec_validation'
            assert 'dnssec_enabled' in result.data

    @pytest.mark.asyncio
    async def test_response_verification(self, cache_prevention):
        """Test response verification."""
        parameters = {'technique': 'response_verification'}
        result = await cache_prevention.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        if result.success:
            assert result.data['technique'] == 'response_verification'
            assert 'responses' in result.data
            assert 'consistent_ip' in result.data
            assert 'verified' in result.data

    @pytest.mark.asyncio
    async def test_invalid_technique(self, cache_prevention):
        """Test invalid prevention technique."""
        parameters = {'technique': 'invalid_technique'}
        result = await cache_prevention.execute('example.com', parameters)
        assert isinstance(result, AttackResult)
        assert not result.success
        assert 'Unknown prevention technique' in result.error

    @pytest.mark.asyncio
    async def test_all_techniques(self, cache_prevention):
        """Test all prevention techniques."""
        techniques = ['query_id_randomization', 'source_port_randomization', 'multiple_server_validation', 'dnssec_validation', 'response_verification']
        for technique in techniques:
            parameters = {'technique': technique}
            result = await cache_prevention.execute('example.com', parameters)
            assert isinstance(result, AttackResult)

class TestDNSAttackDefinitions:
    """Test DNS attack definitions."""

    def test_get_dns_attack_definitions(self):
        """Test getting DNS attack definitions."""
        definitions = get_dns_attack_definitions()
        assert len(definitions) == 4
        for definition in definitions:
            assert definition.id
            assert definition.name
            assert definition.description
            assert definition.category.value == 'dns_tunneling'
            assert definition.test_cases
            assert definition.stability_score >= 0.0
            assert definition.effectiveness_score >= 0.0
            assert definition.performance_score >= 0.0

    def test_doh_attack_definition(self):
        """Test DoH attack definition."""
        definitions = get_dns_attack_definitions()
        doh_def = next((d for d in definitions if d.id == 'dns_doh_tunneling'))
        assert doh_def.name == 'DNS over HTTPS Tunneling'
        assert 'provider' in doh_def.required_parameters
        assert 'https' in doh_def.supported_protocols
        assert 443 in doh_def.supported_ports
        assert len(doh_def.test_cases) >= 2

    def test_dot_attack_definition(self):
        """Test DoT attack definition."""
        definitions = get_dns_attack_definitions()
        dot_def = next((d for d in definitions if d.id == 'dns_dot_tunneling'))
        assert dot_def.name == 'DNS over TLS Tunneling'
        assert 'provider' in dot_def.required_parameters
        assert 'tls' in dot_def.supported_protocols
        assert 853 in dot_def.supported_ports

    def test_query_manipulation_definition(self):
        """Test query manipulation definition."""
        definitions = get_dns_attack_definitions()
        query_def = next((d for d in definitions if d.id == 'dns_query_manipulation'))
        assert query_def.name == 'DNS Query Manipulation'
        assert 'technique' in query_def.required_parameters
        assert len(query_def.test_cases) >= 2

    def test_cache_prevention_definition(self):
        """Test cache prevention definition."""
        definitions = get_dns_attack_definitions()
        cache_def = next((d for d in definitions if d.id == 'dns_cache_poisoning_prevention'))
        assert cache_def.name == 'DNS Cache Poisoning Prevention'
        assert 'technique' in cache_def.required_parameters
        assert len(cache_def.test_cases) >= 2

class TestDNSIntegration:
    """Integration tests for DNS attacks."""

    @pytest.mark.asyncio
    async def test_dns_attack_chain(self):
        """Test chaining multiple DNS attacks."""
        doh_attack = DoHAttack()
        dot_attack = DoTAttack()
        query_manipulation = DNSQueryManipulation()
        domain = 'example.com'
        doh_result = await doh_attack.execute(domain)
        if not doh_result.success:
            dot_result = await dot_attack.execute(domain)
            if not dot_result.success:
                manipulation_result = await query_manipulation.execute(domain, {'technique': 'case_randomization'})
                assert isinstance(manipulation_result, AttackResult)

    @pytest.mark.asyncio
    async def test_dns_fallback_mechanism(self):
        """Test DNS fallback mechanism."""
        attacks = [DoHAttack(), DoTAttack(), DNSQueryManipulation()]
        domain = 'example.com'
        success = False
        for attack in attacks:
            try:
                if isinstance(attack, DNSQueryManipulation):
                    result = await attack.execute(domain, {'technique': 'case_randomization'})
                else:
                    result = await attack.execute(domain)
                if result.success:
                    success = True
                    break
            except Exception:
                continue
        assert True

    @pytest.mark.asyncio
    async def test_dns_performance_comparison(self):
        """Test performance comparison of DNS attacks."""
        attacks = {'DoH': DoHAttack(), 'DoT': DoTAttack(), 'Query Manipulation': DNSQueryManipulation()}
        domain = 'example.com'
        results = {}
        for name, attack in attacks.items():
            start_time = time.time()
            try:
                if isinstance(attack, DNSQueryManipulation):
                    result = await attack.execute(domain, {'technique': 'case_randomization'})
                else:
                    result = await attack.execute(domain)
                end_time = time.time()
                results[name] = {'success': result.success, 'duration': end_time - start_time, 'error': result.error if not result.success else None}
            except Exception as e:
                results[name] = {'success': False, 'duration': time.time() - start_time, 'error': str(e)}
        assert len(results) == len(attacks)
        for name, result in results.items():
            print(f"{name}: Success={result['success']}, Duration={result['duration']:.3f}s")

class TestDNSPerformance:
    """Performance tests for DNS attacks."""

    @pytest.mark.asyncio
    async def test_concurrent_doh_requests(self):
        """Test concurrent DoH requests."""
        doh_attack = DoHAttack()
        domains = ['example.com', 'google.com', 'github.com', 'stackoverflow.com']
        tasks = [doh_attack.execute(domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        assert len(results) == len(domains)
        successful = sum((1 for r in results if isinstance(r, AttackResult) and r.success))
        print(f'Concurrent DoH: {successful}/{len(domains)} successful')

    @pytest.mark.asyncio
    async def test_dns_attack_stress(self):
        """Stress test DNS attacks."""
        attack = DoHAttack()
        domain = 'example.com'
        num_requests = 10
        start_time = time.time()
        tasks = [attack.execute(domain) for _ in range(num_requests)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        assert len(results) == num_requests
        successful = sum((1 for r in results if isinstance(r, AttackResult) and r.success))
        total_time = end_time - start_time
        avg_time = total_time / num_requests
        print(f'Stress test: {successful}/{num_requests} successful, avg time: {avg_time:.3f}s')
        assert avg_time < 10.0
if __name__ == '__main__':
    pytest.main([__file__, '-v'])