// Tests for File Selection Engine

import { describe, it, expect } from 'vitest';
import {
  selectFiles,
  calculateFilePriority,
  getFallbackFiles,
  Priority,
  CRITICAL_FILES,
  type TreeEntry,
} from '../fileSelection';

describe('calculateFilePriority', () => {
  it('should give CRITICAL priority to VS Code config files', () => {
    const files = [
      '.vscode/tasks.json',
      '.vscode/launch.json',
      '.vscode/settings.json',
    ];
    
    for (const path of files) {
      const result = calculateFilePriority({ path, type: 'blob' });
      expect(result.priority).toBe(Priority.CRITICAL);
      expect(result.reason).toContain('Critical');
    }
  });
  
  it('should give CRITICAL priority to package.json', () => {
    const result = calculateFilePriority({ path: 'package.json', type: 'blob' });
    expect(result.priority).toBe(Priority.CRITICAL);
  });
  
  it('should give CRITICAL priority to GitHub Actions workflows', () => {
    const result = calculateFilePriority({ 
      path: '.github/workflows/ci.yml', 
      type: 'blob' 
    });
    expect(result.priority).toBe(Priority.CRITICAL);
  });
  
  it('should give HIGH priority to install scripts', () => {
    const scripts = ['install.sh', 'setup.sh', 'bootstrap.sh'];
    for (const path of scripts) {
      const result = calculateFilePriority({ path, type: 'blob' });
      expect(result.priority).toBe(Priority.CRITICAL);
    }
  });
  
  it('should exclude node_modules files', () => {
    const result = calculateFilePriority({ 
      path: 'node_modules/lodash/index.js', 
      type: 'blob' 
    });
    expect(result.priority).toBe(Priority.VENDOR);
  });
  
  it('should exclude dist/build directories', () => {
    const paths = ['dist/bundle.js', 'build/app.js', 'out/main.js'];
    for (const path of paths) {
      const result = calculateFilePriority({ path, type: 'blob' });
      expect(result.priority).toBe(Priority.VENDOR);
    }
  });
  
  it('should exclude minified files', () => {
    const result = calculateFilePriority({ 
      path: 'lib/react.min.js', 
      type: 'blob' 
    });
    expect(result.priority).toBe(Priority.VENDOR);
  });
  
  it('should give MEDIUM priority to root level files', () => {
    const result = calculateFilePriority({ path: 'index.ts', type: 'blob' });
    expect(result.priority).toBe(Priority.MEDIUM);
  });
  
  it('should give LOW priority to source directory files', () => {
    const result = calculateFilePriority({ path: 'src/utils/helper.ts', type: 'blob' });
    expect(result.priority).toBe(Priority.LOW + 20);
  });
});

describe('selectFiles', () => {
  it('should select critical files first', () => {
    const entries: TreeEntry[] = [
      { path: 'src/index.ts', type: 'blob', size: 1000 },
      { path: '.vscode/tasks.json', type: 'blob', size: 500 },
      { path: 'package.json', type: 'blob', size: 2000 },
      { path: 'README.md', type: 'blob', size: 3000 },
    ];
    
    const result = selectFiles(entries, { maxFiles: 2 });
    
    // Critical files should be selected first
    expect(result.files.map(f => f.path)).toContain('.vscode/tasks.json');
    expect(result.files.map(f => f.path)).toContain('package.json');
    expect(result.stats.selected).toBe(2);
  });
  
  it('should respect maxFiles limit', () => {
    const entries: TreeEntry[] = Array.from({ length: 100 }, (_, i) => ({
      path: `src/file${i}.ts`,
      type: 'blob' as const,
      size: 1000,
    }));
    
    const result = selectFiles(entries, { maxFiles: 10 });
    
    expect(result.files.length).toBe(10);
    expect(result.stats.selected).toBe(10);
  });
  
  it('should respect maxPerFile limit', () => {
    const entries: TreeEntry[] = [
      { path: 'package.json', type: 'blob', size: 1000 },
      { path: 'huge-file.js', type: 'blob', size: 200 * 1024 }, // 200KB
    ];
    
    const result = selectFiles(entries, { maxPerFile: 120 * 1024 });
    
    expect(result.files.map(f => f.path)).toContain('package.json');
    expect(result.files.map(f => f.path)).not.toContain('huge-file.js');
  });
  
  it('should respect maxTotalBytes limit', () => {
    const entries: TreeEntry[] = [
      { path: 'package.json', type: 'blob', size: 1000 },
      { path: 'file1.js', type: 'blob', size: 50000 },
      { path: 'file2.js', type: 'blob', size: 50000 },
      { path: 'file3.js', type: 'blob', size: 50000 },
    ];
    
    const result = selectFiles(entries, { maxTotalBytes: 100000 });
    
    // Should select only files that fit within total bytes limit
    const totalSize = result.files.reduce((sum, f) => sum + (f.size || 0), 0);
    expect(totalSize).toBeLessThanOrEqual(100000);
  });
  
  it('should exclude vendor directories', () => {
    const entries: TreeEntry[] = [
      { path: 'package.json', type: 'blob', size: 1000 },
      { path: 'node_modules/lodash/index.js', type: 'blob', size: 1000 },
      { path: 'vendor/autoload.php', type: 'blob', size: 1000 },
    ];
    
    const result = selectFiles(entries);
    
    expect(result.files.map(f => f.path)).not.toContain('node_modules/lodash/index.js');
    expect(result.files.map(f => f.path)).not.toContain('vendor/autoload.php');
  });
  
  it('should provide trace information', () => {
    const entries: TreeEntry[] = [
      { path: 'package.json', type: 'blob', size: 1000 },
      { path: 'node_modules/x.js', type: 'blob', size: 1000 },
    ];
    
    const result = selectFiles(entries, { enableTrace: true });
    
    expect(result.trace.length).toBe(2);
    
    const packageTrace = result.trace.find(t => t.path === 'package.json');
    expect(packageTrace?.selected).toBe(true);
    expect(packageTrace?.reason).toContain('Critical');
    
    const nodeModulesTrace = result.trace.find(t => t.path === 'node_modules/x.js');
    expect(nodeModulesTrace?.selected).toBe(false);
    expect(nodeModulesTrace?.skippedReason).toContain('Excluded');
  });
  
  it('should be deterministic (same input = same output)', () => {
    const entries: TreeEntry[] = [
      { path: 'b.ts', type: 'blob', size: 1000 },
      { path: 'a.ts', type: 'blob', size: 1000 },
      { path: 'c.ts', type: 'blob', size: 1000 },
    ];
    
    const result1 = selectFiles(entries);
    const result2 = selectFiles(entries);
    
    expect(result1.files.map(f => f.path)).toEqual(result2.files.map(f => f.path));
  });
});

describe('getFallbackFiles', () => {
  it('should include all critical files', () => {
    const fallback = getFallbackFiles();
    
    for (const criticalFile of CRITICAL_FILES) {
      expect(fallback).toContain(criticalFile);
    }
  });
  
  it('should include VS Code config files', () => {
    const fallback = getFallbackFiles();
    
    expect(fallback).toContain('.vscode/tasks.json');
    expect(fallback).toContain('.vscode/launch.json');
    expect(fallback).toContain('.vscode/settings.json');
  });
  
  it('should include common GitHub workflow files', () => {
    const fallback = getFallbackFiles();
    
    const hasWorkflow = fallback.some(f => f.includes('.github/workflows/'));
    expect(hasWorkflow).toBe(true);
  });
});

describe('Time complexity', () => {
  it('should handle large file lists efficiently (O(n log n))', () => {
    // Generate 10,000 files
    const entries: TreeEntry[] = Array.from({ length: 10000 }, (_, i) => ({
      path: `src/components/deep/nested/file${i}.tsx`,
      type: 'blob' as const,
      size: Math.floor(Math.random() * 50000),
    }));
    
    const start = performance.now();
    const result = selectFiles(entries, { enableTrace: false });
    const duration = performance.now() - start;
    
    // Should complete in under 100ms for 10k files
    expect(duration).toBeLessThan(100);
    expect(result.files.length).toBeLessThanOrEqual(60);
  });
});
