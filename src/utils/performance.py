#!/usr/bin/env python3
"""
DAY 10: Performance Optimizer and Caching
Learning: Optimizing analysis speed with caching and parallel processing
Feature: Faster scans for large codebases with intelligent caching
"""

import hashlib
import pickle
import os
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from functools import lru_cache
import threading

class PerformanceOptimizer:
    """Optimizes analysis performance with caching and parallel processing"""
    
    def __init__(self, cache_dir='.security_cache', max_workers=4):
        self.cache_dir = cache_dir
        self.max_workers = max_workers
        self.cache_hits = 0
        self.cache_misses = 0
        self.lock = threading.Lock()
        
        # Create cache directory
        os.makedirs(cache_dir, exist_ok=True)
        
        # Clean old cache entries on startup
        self._clean_old_cache()
    
    def get_file_hash(self, filepath):
        """Calculate MD5 hash of file for cache key"""
        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.md5()
                # Read in chunks for large files
                for chunk in iter(lambda: f.read(4096), b''):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception as e:
            print(f"⚠️  Error calculating hash for {filepath}: {e}")
            return None
    
    def get_cache_key(self, filepath, analyzer_name):
        """Generate cache key from file hash and analyzer"""
        file_hash = self.get_file_hash(filepath)
        if not file_hash:
            return None
        
        # Include analyzer name and file modification time in key
        try:
            mtime = os.path.getmtime(filepath)
            key = f"{analyzer_name}_{file_hash}_{int(mtime)}"
            return hashlib.md5(key.encode()).hexdigest()
        except:
            return None
    
    def get_cached_result(self, cache_key):
        """Get cached analysis result if exists and valid"""
        if not cache_key:
            return None
        
        cache_file = os.path.join(self.cache_dir, f"{cache_key}.cache")
        
        try:
            if os.path.exists(cache_file):
                # Check if cache is still valid (24 hours)
                cache_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(cache_file))
                if cache_age < timedelta(hours=24):
                    with open(cache_file, 'rb') as f:
                        result = pickle.load(f)
                    
                    with self.lock:
                        self.cache_hits += 1
                    return result
                else:
                    # Cache expired, remove it
                    os.remove(cache_file)
        except Exception as e:
            print(f"⚠️  Error reading cache: {e}")
        
        with self.lock:
            self.cache_misses += 1
        return None
    
    def cache_result(self, cache_key, result):
        """Cache analysis result"""
        if not cache_key:
            return False
        
        try:
            cache_file = os.path.join(self.cache_dir, f"{cache_key}.cache")
            with open(cache_file, 'wb') as f:
                pickle.dump(result, f)
            return True
        except Exception as e:
            print(f"⚠️  Error caching result: {e}")
            return False
    
    def analyze_file_with_cache(self, filepath, analyzer_func, analyzer_name):
        """Analyze file with caching"""
        cache_key = self.get_cache_key(filepath, analyzer_name)
        
        # Try to get from cache first
        cached_result = self.get_cached_result(cache_key)
        if cached_result is not None:
            return cached_result
        
        # If not in cache, analyze
        start_time = time.time()
        result = analyzer_func(filepath)
        analysis_time = time.time() - start_time
        
        # Cache the result
        if cache_key and analysis_time > 0.1:  # Only cache if analysis took meaningful time
            self.cache_result(cache_key, result)
        
        return result
    
    def analyze_files_parallel(self, filepaths, analyzer_func, analyzer_name):
        """Analyze multiple files in parallel"""
        results = []
        
        # Use ThreadPoolExecutor for I/O bound operations
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all analysis tasks
            future_to_file = {
                executor.submit(
                    self.analyze_file_with_cache, 
                    filepath, 
                    lambda fp: analyzer_func(fp), 
                    analyzer_name
                ): filepath 
                for filepath in filepaths
            }
            
            # Collect results as they complete
            for future in future_to_file:
                try:
                    result = future.result()
                    results.extend(result)
                except Exception as e:
                    filepath = future_to_file[future]
                    print(f"❌ Error analyzing {filepath}: {e}")
        
        return results
    
    def batch_analyze(self, filepaths, analyzers):
        """Batch analyze files with multiple analyzers"""
        all_results = []
        
        for analyzer_name, analyzer_func in analyzers.items():
            print(f"🔍 Running {analyzer_name.upper()} analyzer on {len(filepaths)} files...")
            
            start_time = time.time()
            results = self.analyze_files_parallel(filepaths, analyzer_func, analyzer_name)
            elapsed = time.time() - start_time
            
            print(f"   ⏱️  {analyzer_name.upper()}: {len(results)} findings in {elapsed:.2f}s")
            all_results.extend(results)
        
        return all_results
    
    def get_performance_stats(self):
        """Get performance statistics"""
        cache_files = [f for f in os.listdir(self.cache_dir) if f.endswith('.cache')]
        
        stats = {
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_size': len(cache_files),
            'cache_hit_rate': self.cache_hits / (self.cache_hits + self.cache_misses) if (self.cache_hits + self.cache_misses) > 0 else 0
        }
        
        return stats
    
    def clear_cache(self):
        """Clear all cached results"""
        try:
            for file in os.listdir(self.cache_dir):
                if file.endswith('.cache'):
                    os.remove(os.path.join(self.cache_dir, file))
            print(f"✅ Cleared cache directory: {self.cache_dir}")
            return True
        except Exception as e:
            print(f"❌ Error clearing cache: {e}")
            return False
    
    def _clean_old_cache(self):
        """Clean cache entries older than 7 days"""
        try:
            cutoff_time = time.time() - (7 * 24 * 60 * 60)  # 7 days
            
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.cache'):
                    filepath = os.path.join(self.cache_dir, filename)
                    if os.path.getmtime(filepath) < cutoff_time:
                        os.remove(filepath)
        except:
            pass  # Silent fail for cache cleaning
    
    @lru_cache(maxsize=128)
    def parse_ast_cached(self, code):
        """Cached AST parsing for frequently analyzed code patterns"""
        import ast
        try:
            return ast.parse(code)
        except:
            return None

class ProgressTracker:
    """Tracks and displays analysis progress"""
    
    def __init__(self, total_files):
        self.total_files = total_files
        self.completed_files = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
    
    def update(self, files_completed=1):
        """Update progress"""
        with self.lock:
            self.completed_files += files_completed
            
            # Calculate progress
            percentage = (self.completed_files / self.total_files) * 100
            elapsed = time.time() - self.start_time
            
            # Estimate remaining time
            if self.completed_files > 0:
                files_per_second = self.completed_files / elapsed
                remaining_files = self.total_files - self.completed_files
                remaining_time = remaining_files / files_per_second if files_per_second > 0 else 0
                
                # Display progress
                print(f"\r📊 Progress: {self.completed_files}/{self.total_files} files "
                      f"({percentage:.1f}%) | "
                      f"Elapsed: {elapsed:.1f}s | "
                      f"ETA: {remaining_time:.1f}s", end='', flush=True)
    
    def finish(self):
        """Finish progress tracking"""
        elapsed = time.time() - self.start_time
        print(f"\n✅ Analysis completed in {elapsed:.2f} seconds")
        print(f"   Files per second: {self.total_files/elapsed:.2f}" if elapsed > 0 else "")
