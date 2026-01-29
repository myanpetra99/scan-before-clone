// Tests for JSONC Parser

import { describe, it, expect } from 'vitest';
import { parseJsonc, stripJsonComments, removeTrailingCommas } from '../jsonc';

describe('stripJsonComments', () => {
  it('should remove single-line comments', () => {
    const input = `{
      // This is a comment
      "key": "value"
    }`;
    
    const result = stripJsonComments(input);
    
    expect(result).not.toContain('//');
    expect(result).toContain('"key"');
  });
  
  it('should remove block comments', () => {
    const input = `{
      /* This is a
         block comment */
      "key": "value"
    }`;
    
    const result = stripJsonComments(input);
    
    expect(result).not.toContain('/*');
    expect(result).not.toContain('*/');
    expect(result).toContain('"key"');
  });
  
  it('should preserve // inside strings', () => {
    const input = `{
      "url": "https://example.com"
    }`;
    
    const result = stripJsonComments(input);
    
    expect(result).toContain('https://example.com');
  });
  
  it('should handle inline comments', () => {
    const input = `{
      "key": "value" // inline comment
    }`;
    
    const result = stripJsonComments(input);
    
    expect(result).not.toContain('inline comment');
    expect(result).toContain('"value"');
  });
});

describe('removeTrailingCommas', () => {
  it('should remove trailing comma before }', () => {
    const input = '{ "key": "value", }';
    const result = removeTrailingCommas(input);
    
    expect(result).toBe('{ "key": "value" }');
  });
  
  it('should remove trailing comma before ]', () => {
    const input = '["a", "b", ]';
    const result = removeTrailingCommas(input);
    
    expect(result).toBe('["a", "b" ]');
  });
  
  it('should handle nested structures', () => {
    const input = '{ "arr": [1, 2, ], "obj": { "x": 1, }, }';
    const result = removeTrailingCommas(input);
    
    expect(result).toBe('{ "arr": [1, 2 ], "obj": { "x": 1 } }');
  });
});

describe('parseJsonc', () => {
  it('should parse valid JSON', () => {
    const input = '{"key": "value"}';
    const result = parseJsonc<{ key: string }>(input);
    
    expect(result).toEqual({ key: 'value' });
  });
  
  it('should parse JSONC with comments', () => {
    const input = `{
      // Comment
      "key": "value"
    }`;
    
    const result = parseJsonc<{ key: string }>(input);
    
    expect(result).toEqual({ key: 'value' });
  });
  
  it('should parse JSONC with trailing commas', () => {
    const input = `{
      "key": "value",
    }`;
    
    const result = parseJsonc<{ key: string }>(input);
    
    expect(result).toEqual({ key: 'value' });
  });
  
  it('should parse complex JSONC', () => {
    const input = `{
      // VS Code tasks config
      "version": "2.0.0",
      "tasks": [
        {
          "label": "Build", /* Build task */
          "type": "shell",
          "command": "npm run build",
        },
      ],
    }`;
    
    const result = parseJsonc<{
      version: string;
      tasks: Array<{ label: string; type: string; command: string }>;
    }>(input);
    
    expect(result?.version).toBe('2.0.0');
    expect(result?.tasks).toHaveLength(1);
    expect(result?.tasks[0].label).toBe('Build');
  });
  
  it('should return null for invalid JSON', () => {
    const input = '{ invalid }';
    const result = parseJsonc(input);
    
    expect(result).toBeNull();
  });
  
  it('should handle empty string', () => {
    const result = parseJsonc('');
    expect(result).toBeNull();
  });
});
