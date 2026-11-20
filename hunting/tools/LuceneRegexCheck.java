/*
 * Compile every RLIKE and LIKE pattern of the hunting pack with Lucene, the regex engine
 * Elasticsearch uses, the same way ES|QL does: RegExp with all optional operators, then
 * determinize with the default work limit. This catches what the static checker cannot:
 *
 *   - "Invalid regex" errors (a bare double quote, an empty alternative such as "(x|)",
 *     a dash at the end of a character class read as a range, unbalanced parentheses);
 *   - "too complex to determinize" errors, which one alternation holding several ".*" pairs
 *     usually causes. Split such a pattern into several RLIKE / LIKE tests joined with OR;
 *     ES|QL compiles each one separately.
 *
 * A pattern list, LIKE ("a*", "b*") or RLIKE ("x.*", "y.*") (Elasticsearch 9.1+), is compiled
 * the way ES|QL compiles it: one automaton, the union of every pattern, determinized as a whole.
 * Long lists (the generated LOLRMM queries) are therefore split into several lists joined with OR.
 *
 * Usage (Java 11+, no build step; download lucene-core once):
 *   curl -sSfO https://repo1.maven.org/maven2/org/apache/lucene/lucene-core/10.2.2/lucene-core-10.2.2.jar
 *   java -cp lucene-core-10.2.2.jar hunting/tools/LuceneRegexCheck.java hunting/queries
 *
 * Exit status is 0 when every pattern compiles.
 */
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.lucene.util.automaton.Automata;
import org.apache.lucene.util.automaton.Automaton;
import org.apache.lucene.util.automaton.Operations;
import org.apache.lucene.util.automaton.RegExp;

public class LuceneRegexCheck {

    // RLIKE / LIKE followed by a "..." or """...""" literal (same rule as check_queries.py)
    private static final Pattern LITERAL = Pattern.compile(
        "\\b(RLIKE|LIKE)\\s+(\"\"\"[\\s\\S]*?\"\"\"|\"(?:[^\"\\\\]|\\\\.)*\")");
    // RLIKE / LIKE followed by "(": a pattern list, whose literals are read by listItems()
    private static final Pattern LIST = Pattern.compile("\\b(RLIKE|LIKE)\\s*\\(");

    public static void main(String[] args) throws IOException {
        Path root = Paths.get(args.length > 0 ? args[0] : "hunting/queries");
        List<Path> files;
        try (Stream<Path> s = Files.walk(root)) {
            files = s.filter(p -> p.toString().endsWith(".esql")).sorted().collect(Collectors.toList());
        }
        int patterns = 0;
        int failures = 0;
        for (Path file : files) {
            String raw = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
            Matcher m = LITERAL.matcher(raw);
            while (m.find()) {
                patterns++;
                String kind = m.group(1);
                String lit = m.group(2);
                String pat = lit.startsWith("\"\"\"") ? lit.substring(3, lit.length() - 3) : unescape(lit.substring(1, lit.length() - 1));
                int line = 1;
                for (int i = 0; i < m.start(); i++) {
                    if (raw.charAt(i) == '\n') {
                        line++;
                    }
                }
                try {
                    Automaton a = kind.equals("RLIKE")
                        ? new RegExp(pat, RegExp.ALL | RegExp.DEPRECATED_COMPLEMENT).toAutomaton()
                        : wildcard(pat);
                    Operations.determinize(a, Operations.DEFAULT_DETERMINIZE_WORK_LIMIT);
                } catch (RuntimeException e) {
                    failures++;
                    System.out.println(file + ":" + line + ": " + kind + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
        }
        for (Path file : files) {
            String raw = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
            Matcher m = LIST.matcher(raw);
            while (m.find()) {
                patterns++;
                String kind = m.group(1);
                int line = 1;
                for (int i = 0; i < m.start(); i++) {
                    if (raw.charAt(i) == '\n') {
                        line++;
                    }
                }
                List<Automaton> parts = new ArrayList<>();
                try {
                    for (String lit : listItems(raw, m.end())) {
                        String pat = unescape(lit);
                        parts.add(kind.equals("RLIKE")
                            ? new RegExp(pat, RegExp.ALL | RegExp.DEPRECATED_COMPLEMENT).toAutomaton()
                            : wildcard(pat));
                    }
                    Operations.determinize(Operations.union(parts), Operations.DEFAULT_DETERMINIZE_WORK_LIMIT);
                } catch (RuntimeException e) {
                    failures++;
                    System.out.println(file + ":" + line + ": " + kind + " list of " + parts.size() + ": "
                        + e.getClass().getSimpleName() + ": " + e.getMessage());
                }
            }
        }
        System.out.println(files.size() + " queries, " + patterns + " patterns or pattern lists checked, " + failures + " failure(s)");
        System.exit(failures == 0 ? 0 : 1);
    }

    // the "..." literals of a pattern list, from just after its "(" to the closing ")"
    private static List<String> listItems(String raw, int from) {
        List<String> items = new ArrayList<>();
        int i = from;
        while (i < raw.length()) {
            char c = raw.charAt(i);
            if (c == ')') {
                return items;
            }
            if (c == '"') {
                StringBuilder b = new StringBuilder();
                i++;
                while (i < raw.length() && raw.charAt(i) != '"') {
                    if (raw.charAt(i) == '\\' && i + 1 < raw.length()) {
                        b.append(raw.charAt(i)).append(raw.charAt(i + 1));
                        i += 2;
                    } else {
                        b.append(raw.charAt(i++));
                    }
                }
                items.add(b.toString());
            } else if (!Character.isWhitespace(c) && c != ',') {
                throw new IllegalArgumentException("not a list of string literals at offset " + i);
            }
            i++;
        }
        throw new IllegalArgumentException("unterminated pattern list");
    }

    // ES|QL string literal escapes: \\ \" \n \t \r
    private static String unescape(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                b.append(n == 'n' ? '\n' : n == 't' ? '\t' : n == 'r' ? '\r' : n);
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }

    // ES|QL LIKE: * any string, ? any character, backslash escapes the next character
    private static Automaton wildcard(String s) {
        List<Automaton> parts = new ArrayList<>();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '*') {
                parts.add(Automata.makeAnyString());
            } else if (c == '?') {
                parts.add(Automata.makeAnyChar());
            } else {
                if (c == '\\' && i + 1 < s.length()) {
                    c = s.charAt(++i);
                }
                parts.add(Automata.makeChar(c));
            }
        }
        return parts.isEmpty() ? Automata.makeEmptyString() : Operations.concatenate(parts);
    }
}
