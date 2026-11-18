"""
Scalability Simulator Engine
Measures performance and execution metrics for large-scale smart meter simulations.
Designed for Academic Demonstration - Scalable KDC RSA System
"""

import time
import random
from rsa import generate_rsa_keys
from extended_euclid import mod_inverse


def run_kdc_simulation(num_meters: int, architecture_mode: str = "HIERARCHICAL", key_bits: int = 16) -> dict:
    """
    Executes a benchmark simulation for key generation and registration across virtual smart meters.
    
    Args:
        num_meters: Number of virtual meters to simulate (e.g. 100, 500, 1000, 5000, 10000)
        architecture_mode: "HIERARCHICAL" (distributed regional processing) or "CENTRALIZED"
        key_bits: RSA prime bit length (default 16 for fast benchmark scaling)
        
    Returns:
        dict containing timing, throughput, and success/failure metrics.
    """
    start_time = time.perf_counter()
    
    regions = ["R1", "R2", "R3", "R4", "R5"]
    successful_ops = 0
    failed_ops = 0
    
    # Regional Distribution Buckets
    region_counts = {r: 0 for r in regions}
    
    for i in range(1, num_meters + 1):
        try:
            meter_id = f"SIM_{i:05d}"
            
            # Select Region
            if architecture_mode == "HIERARCHICAL":
                # Distributed workload across regional KDCs
                assigned_region = regions[i % len(regions)]
            else:
                # Centralized KDC handles all directly under a single root node
                assigned_region = "CENTRAL_ROOT"
                
            if assigned_region in region_counts:
                region_counts[assigned_region] += 1
            else:
                region_counts[assigned_region] = 1

            # Generate RSA Keys for the virtual meter
            rsa_keys = generate_rsa_keys(bits=key_bits)
            
            if rsa_keys and 'public_key' in rsa_keys:
                successful_ops += 1
            else:
                failed_ops += 1

        except Exception:
            failed_ops += 1

    end_time = time.perf_counter()
    total_time_sec = end_time - start_time
    
    # Calculate performance metrics
    avg_time_ms = (total_time_sec / num_meters) * 1000.0 if num_meters > 0 else 0.0
    ops_per_sec = (successful_ops / total_time_sec) if total_time_sec > 0 else 0.0

    return {
        'success': True,
        'count': num_meters,
        'mode': architecture_mode,
        'total_time_sec': round(total_time_sec, 4),
        'avg_time_ms': round(avg_time_ms, 4),
        'ops_per_sec': round(ops_per_sec, 2),
        'successful_ops': successful_ops,
        'failed_ops': failed_ops,
        'regional_distribution': region_counts
    }