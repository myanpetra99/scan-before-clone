// JSONC Parser - JSON with Comments (used by VS Code configs)
// Safely handles JSON files that may contain single-line comments,
// block comments, and trailing commas

/**
 * Remove comments from JSONC string
 * Handles both single-line and block comment styles
 */
export function stripJsonComments(jsonc: string): string {
  let result = '';
  let i = 0;
  let inString = false;
  let stringChar = '';
  
  while (i < jsonc.length) {
    const char = jsonc[i];
    const nextChar = jsonc[i + 1];
    
    // Handle string state
    if (inString) {
      result += char;
      if (char === '\\' && i + 1 < jsonc.length) {
        // Skip escaped character
        result += nextChar;
        i += 2;
        continue;
      }
      if (char === stringChar) {
        inString = false;
      }
      i++;
      continue;
    }
    
    // Check for string start
    if (char === '"' || char === "'") {
      inString = true;
      stringChar = char;
      result += char;
      i++;
      continue;
    }
    
    // Check for single-line comment
    if (char === '/' && nextChar === '/') {
      // Skip until end of line
      while (i < jsonc.length && jsonc[i] !== '\n') {
        i++;
      }
      continue;
    }
    
    // Check for block comment
    if (char === '/' && nextChar === '*') {
      i += 2;
      // Skip until */
      while (i < jsonc.length - 1) {
        if (jsonc[i] === '*' && jsonc[i + 1] === '/') {
          i += 2;
          break;
        }
        i++;
      }
      continue;
    }
    
    result += char;
    i++;
  }
  
  return result;
}

/**
 * Remove trailing commas from JSON
 */
export function removeTrailingCommas(json: string): string {
  // Match comma followed by whitespace and closing bracket/brace
  return json.replace(/,(\s*[}\]])/g, '$1');
}

/**
 * Clean malformed JSON that uses line continuations or other obfuscation
 * This handles VS Code config files that use backslash line continuations
 */
export function cleanMalformedJson(json: string): string {
  let cleaned = json;
  
  // Remove backslash line continuations (malicious obfuscation technique)
  cleaned = cleaned.replace(/\\\s*\n/g, '');
  
  // Remove trailing content after the main JSON object closes
  // Find the position where the main object/array ends
  let depth = 0;
  let mainEnd = -1;
  let inString = false;
  let stringChar = '';
  
  for (let i = 0; i < cleaned.length; i++) {
    const char = cleaned[i];
    
    // Handle string state
    if (inString) {
      if (char === '\\' && i + 1 < cleaned.length) {
        i++; // Skip escaped char
        continue;
      }
      if (char === stringChar) {
        inString = false;
      }
      continue;
    }
    
    if (char === '"' || char === "'") {
      inString = true;
      stringChar = char;
      continue;
    }
    
    if (char === '{' || char === '[') {
      depth++;
    } else if (char === '}' || char === ']') {
      depth--;
      if (depth === 0) {
        mainEnd = i + 1;
        break;
      }
    }
  }
  
  // Truncate anything after the main JSON structure
  if (mainEnd > 0 && mainEnd < cleaned.length) {
    cleaned = cleaned.substring(0, mainEnd);
  }
  
  return cleaned;
}

/**
 * Parse JSONC string to object
 * Handles comments, trailing commas, and malformed/obfuscated JSON
 */
export function parseJsonc<T = unknown>(jsonc: string): T | null {
  try {
    // First try standard JSON parse (fast path for valid JSON)
    return JSON.parse(jsonc) as T;
  } catch {
    // Fall back to cleaning and parsing
    try {
      // Step 1: Clean malformed JSON (line continuations, trailing garbage)
      let cleaned = cleanMalformedJson(jsonc);
      // Step 2: Strip comments
      cleaned = stripJsonComments(cleaned);
      // Step 3: Remove trailing commas
      cleaned = removeTrailingCommas(cleaned);
      return JSON.parse(cleaned) as T;
    } catch (e) {
      console.warn('Failed to parse JSONC:', e);
      return null;
    }
  }
}

/**
 * Safely get nested property from object
 */
export function getNestedValue<T>(obj: unknown, path: string): T | undefined {
  const keys = path.split('.');
  let current: unknown = obj;
  
  for (const key of keys) {
    if (current === null || current === undefined) {
      return undefined;
    }
    if (typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[key];
  }
  
  return current as T;
}
