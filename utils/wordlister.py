#!/usr/bin/env python3
"""
EZPZ Wordlist Generator for CTF
Generates mutated wordlists with various transformations for penetration testing.
"""

import sys
import argparse
from itertools import product, combinations_with_replacement
from pathlib import Path


class Colors:
    """ANSI color codes matching ezpz_colors.fish"""
    YELLOW_BOLD = '\033[1;33m'    # ezpz_header [+]
    CYAN = '\033[36m'             # ezpz_info [*]
    BLUE = '\033[34m'             # ezpz_cmd [>]
    RED_BOLD = '\033[1;31m'       # ezpz_error [!]
    RED = '\033[31m'              # ezpz_warn [-]
    MAGENTA_BOLD = '\033[1;35m'   # ezpz_success [✓], ezpz_title [~]
    RESET = '\033[0m'             # reset colors
    
    @staticmethod
    def header(msg):
        return f"{Colors.YELLOW_BOLD}[+] {msg}{Colors.RESET}"
    
    @staticmethod
    def info(msg):
        return f"{Colors.CYAN}[*] {msg}{Colors.RESET}"
    
    @staticmethod
    def cmd(msg):
        return f"{Colors.BLUE}[>] {msg}{Colors.RESET}"
    
    @staticmethod
    def error(msg):
        return f"{Colors.RED_BOLD}[!] {msg}{Colors.RESET}"


class WordlistGenerator:
    def __init__(self):
        self.default_words = [
            # Seasons
            'summer', 'spring', 'winter', 'fall', 'autumn',
            # Months
            'january', 'february', 'march', 'april', 'may', 'june',
            'july', 'august', 'september', 'october', 'november', 'december'
        ]
        
        self.user_words = []
        
        self.leet_substitutions = {
            'o': ['0'],
            'a': ['@'],
            'e': ['3'],
            's': ['$'],
            'i': ['1']
        }
        
        self.symbols = ['!', '@', '#', '$', '%', '&', '*', '-', '+', '=']
        self.wordlist = set()

    def load_base_wordlist(self, filepath):
        """Load additional words from base wordlist file."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip().lower()
                    if word and word.isalpha():
                        self.user_words.append(word)
        except FileNotFoundError:
            print(Colors.error(f"Base wordlist file not found: {filepath}"))
            sys.exit(1)

    def apply_capitalization(self, word):
        """Generate capitalization variations."""
        variations = [
            word.lower(),   # original lowercase
            word.title(),   # Title case  
            word.upper()    # UPPER case
        ]
            
        return list(set(variations))


    def generate_leet_variants(self, word):
        """Generate all possible leetspeak combinations."""
        variants = set([word])
        word_lower = word.lower()
        
        # Find positions where substitutions can be made
        substitution_positions = {}
        for i, char in enumerate(word_lower):
            if char in self.leet_substitutions:
                substitution_positions[i] = self.leet_substitutions[char]
        
        if not substitution_positions:
            return [word]
        
        # Generate all combinations of substitutions
        positions = list(substitution_positions.keys())
        
        # For each combination of positions to substitute
        for r in range(1, len(positions) + 1):
            for pos_combo in combinations_with_replacement(positions, r):
                # Remove duplicates while preserving order
                unique_positions = []
                seen = set()
                for pos in pos_combo:
                    if pos not in seen:
                        unique_positions.append(pos)
                        seen.add(pos)
                
                # Generate all substitution combinations for these positions
                substitution_options = [substitution_positions[pos] for pos in unique_positions]
                
                for substitution_combo in product(*substitution_options):
                    variant = list(word_lower)
                    for pos, substitution in zip(unique_positions, substitution_combo):
                        variant[pos] = substitution
                    variants.add(''.join(variant))
        
        return list(variants)

    def generate_word_combinations(self, user_words, default_words):
        """Generate combinations of 1-2 words, mixing user and default words."""
        combinations = set()
        # Remove duplicates when combining lists
        all_words = list(set(user_words + default_words))
        
        # Single words
        for word in all_words:
            combinations.add(word)
        
        # Two word combinations: user + user, user + default (not default + user)
        for word1 in all_words:
            for word2 in all_words:
                # Avoid default + default combinations and default + any
                if word1 in default_words:
                    continue
                combinations.add(word1 + word2)
        
        return list(combinations)

    def add_numeric_suffixes(self, words):
        """Add 1-4 digit numeric suffixes."""
        result = set(words)
        
        for word in words:
            # 1 digit: 0-9
            for i in range(10):
                result.add(f"{word}{i}")
            
            # 2 digits: 00-99 (all)
            for i in range(100):
                result.add(f"{word}{i:02d}")
            
            # 3 digits: common numbers
            common_3digit = [
                100, 101, 111, 123, 222, 321, 333, 420, 444, 555, 666, 777, 888, 999,
                7, 42, 69, 80, 88, 404, 500, 911
            ]
            for i in common_3digit:
                result.add(f"{word}{i:03d}")
            
            # 4 digits: years
            for year in range(1980, 2031):
                result.add(f"{word}{year}")
        
        return list(result)

    def add_symbol_suffixes(self, words):
        """Add 1-3 symbol suffixes."""
        result = set(words)
        
        for word in words:
            # Single symbols (all)
            for symbol in self.symbols:
                result.add(f"{word}{symbol}")
            
            # Two symbols (common combinations)
            common_double = ['!!', '@@', '##', '$$', '**', '++', '==', '!@', '@!', '!#', 
                           '!=', '#!', '$!', '%!', '&!', '*!', '-!', '+!', '=!']
            for combo in common_double:
                result.add(f"{word}{combo}")
            
            # Three symbols (very common)
            common_triple = ['!!!', '@@@', '###', '***', '!@#', '!##', '@@!', '**!']
            for combo in common_triple:
                result.add(f"{word}{combo}")
        
        return list(result)

    def generate_wordlist(self, base_file, fast_mode=False, min_length=1):
        """Main wordlist generation pipeline."""
        
        # Load base words
        if base_file:
            self.load_base_wordlist(base_file)
        
        # Choose word sources based on fast mode
        if fast_mode:
            all_base_words = self.user_words
            print(Colors.info(f"Fast mode: Processing {len(all_base_words)} user words only..."))
        else:
            all_base_words = self.user_words + self.default_words
        
        # Step 1: Apply capitalization to all base words
        cap_words = []
        for word in all_base_words:
            cap_words.extend(self.apply_capitalization(word))
        
        print(Colors.cmd(f"Generated {len(cap_words)} capitalization variants"))
        
        # Step 2: Apply leetspeak (skip in fast mode)
        if fast_mode:
            leet_words = cap_words
            print(Colors.cmd(f"Fast mode: Skipping leetspeak"))
        else:
            leet_words = []
            for word in cap_words:
                leet_words.extend(self.generate_leet_variants(word))
            print(Colors.cmd(f"Generated {len(leet_words)} leetspeak variants"))
        
        # Step 3: Generate word combinations
        if fast_mode:
            # Fast mode: only user word combinations (no default words)
            user_leet = leet_words  # All words are user words in fast mode
            combo_words = self.generate_word_combinations(user_leet, [])
            print(Colors.cmd(f"Fast mode: Generated {len(combo_words)} user-only combinations"))
        else:
            user_leet = [w for w in leet_words if any(base in w.lower() for base in self.user_words)]
            default_leet = [w for w in leet_words if any(base in w.lower() for base in self.default_words)]
            
            combo_words = self.generate_word_combinations(user_leet, default_leet)
            print(Colors.cmd(f"Generated {len(combo_words)} word combinations"))
        
        # Step 4: Add numeric suffixes
        numeric_words = self.add_numeric_suffixes(combo_words)
        print(Colors.cmd(f"Generated {len(numeric_words)} numeric variants"))
        
        # Step 5: Add symbol suffixes
        symbol_words = self.add_symbol_suffixes(numeric_words)
        print(Colors.cmd(f"Generated {len(symbol_words)} symbol variants"))
        
        # Step 6: Filter by minimum length
        if min_length > 1:
            final_words = [word for word in symbol_words if len(word) >= min_length]
            print(Colors.info(f"Filtered by minimum length {min_length}: {len(final_words)} words"))
        else:
            final_words = symbol_words
        
        return sorted(set(final_words))

    def save_wordlist(self, words, output_file):
        """Save the generated wordlist to file."""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for word in words:
                    f.write(f"{word}\n")
            print(Colors.header(f"Saved {len(words)} words to {output_file}"))
        except Exception as e:
            print(Colors.error(f"Error saving wordlist: {e}"))
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Generate mutated wordlists for CTF')
    parser.add_argument('input_file', nargs='?', help='Base wordlist file (optional)')
    parser.add_argument('-o', '--output', help='Output file (default: input_mutated.txt)')
    parser.add_argument('--min', type=int, default=1, help='Minimum password length (default: 1)')
    parser.add_argument('-F', '--fast', action='store_true', help='Fast mode: skip leetspeak and default words')
    
    args = parser.parse_args()
    
    generator = WordlistGenerator()
    
    # Determine output filename
    if args.output:
        output_file = args.output
    elif args.input_file:
        input_path = Path(args.input_file)
        output_file = input_path.parent / f"{input_path.stem}_mutated.txt"
    else:
        output_file = "ezpz_wordlist_mutated.txt"
    
    # Generate wordlist
    words = generator.generate_wordlist(args.input_file, fast_mode=args.fast, min_length=args.min)
    
    # Save results
    generator.save_wordlist(words, output_file)


if __name__ == "__main__":
    main()