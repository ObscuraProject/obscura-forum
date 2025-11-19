#!/usr/bin/env python3
"""
Prestimos Obscura Forum - Proof of Work Solver
This script helps users solve the proof of work challenge without JavaScript.

Usage:
    python3 pow_solver.py <challenge_token> <difficulty>

Example:
    python3 pow_solver.py abc123def456 4

The script will find a nonce that when combined with the token produces a SHA256 hash
starting with the required number of zeros.
"""

import hashlib
import sys
import time

def solve_pow(challenge_token, difficulty):
    """
    Solve proof of work challenge by finding a nonce that produces the required hash.
    
    Args:
        challenge_token: The challenge token from the gateway
        difficulty: Number of leading zeros required in the hash
    
    Returns:
        tuple: (nonce, hash_result, iterations)
    """
    nonce = 0
    start_time = time.time()
    iterations = 0
    target_prefix = '0' * difficulty
    
    print(f"🔍 Solving PoW Challenge...")
    print(f"   Token: {challenge_token}")
    print(f"   Difficulty: {difficulty} zeros")
    print(f"   Target: Hash starting with '{target_prefix}'")
    print(f"\n⏳ Computing... (this may take a minute or two)")
    
    while True:
        iterations += 1
        
        # Create data to hash: token:nonce
        data = f"{challenge_token}:{nonce}"
        
        # Calculate SHA256 hash
        hash_obj = hashlib.sha256(data.encode())
        hash_hex = hash_obj.hexdigest()
        
        # Print progress every 10000 iterations
        if iterations % 10000 == 0:
            elapsed = time.time() - start_time
            rate = iterations / elapsed
            print(f"   Tried {iterations:,} nonces ({rate:.0f} per second)...")
        
        # Check if hash meets difficulty
        if hash_hex.startswith(target_prefix):
            elapsed = time.time() - start_time
            print(f"\n✅ Solution found!")
            print(f"   Nonce: {nonce}")
            print(f"   Hash: {hash_hex}")
            print(f"   Iterations: {iterations:,}")
            print(f"   Time elapsed: {elapsed:.2f} seconds")
            print(f"   Average rate: {iterations/elapsed:.0f} hashes/second")
            return nonce, hash_hex, iterations
        
        nonce += 1

def main():
    """Main entry point"""
    if len(sys.argv) < 3:
        print("Usage: python3 pow_solver.py <challenge_token> <difficulty>")
        print("\nExample:")
        print("  python3 pow_solver.py abc123def456 4")
        print("\nThis will solve the proof of work challenge and output the nonce.")
        print("Then paste the nonce into the forum's proof of work gateway form.")
        sys.exit(1)
    
    challenge_token = sys.argv[1]
    try:
        difficulty = int(sys.argv[2])
    except ValueError:
        print("Error: difficulty must be an integer")
        sys.exit(1)
    
    if difficulty < 1 or difficulty > 10:
        print("Error: difficulty should be between 1 and 10")
        sys.exit(1)
    
    print("🌑 Prestimos Obscura Forum - Proof of Work Solver\n")
    
    nonce, hash_result, iterations = solve_pow(challenge_token, difficulty)
    
    print("\n" + "="*60)
    print("📝 Submit this nonce to the forum gateway:")
    print("="*60)
    print(f"\nNonce to submit: {nonce}\n")
    print("="*60)

if __name__ == '__main__':
    main()