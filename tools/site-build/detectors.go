package main

// Detector pattern extraction.
//
// Parses internal/detector/** with go/ast and emits site/js/detectors.js, the
// data the in-browser playground scanner uses. Each detector contributes its
// ID, default severity, Aho-Corasick keywords, and the regex pattern(s) its
// Scan method references. Go uses RE2 (no look-around / back-references), which
// is a clean subset of JavaScript's regex syntax, so the patterns port over;
// a small normalization step handles the few Go-specific tokens.
//
// Gating vs. triggering patterns
//
// A detector's Scan method often references more than one package-level
// regexp var, but not every one of them is an independent, OR'd trigger:
//   - A pattern used only as the receiver of Match/MatchString inside a guard
//     clause (e.g. `if !contextPattern.Match(data) { return nil }`) is a
//     *gate*: it must hold for the rest of Scan to run, but reporting it as
//     its own standalone finding in the playground is wrong (see the okta,
//     mailgun context-pattern findings in review section 28).
//   - A pattern referenced only as a plain function-call argument (never as
//     a method-call receiver, e.g. `extractSubmatch(privateKeyIDPattern,
//     block)`) is used for metadata extraction only, not detection (see the
//     gcp-service-account finding).
//   - A pattern whose only match-producing call
//     (Find/FindAll/FindSubmatch/... family) sits inside the *body* of an
//     `if` statement — as opposed to running unconditionally, e.g. after an
//     early-return guard clause — is conditionally gated by something the
//     static extractor cannot safely encode as an unconditional OR'd trigger
//     (see the notion-token `secret_` pattern, gated by
//     `detector.HasAnyKeyword(data, "notion")`).
//
// extractDetectors classifies every pattern reference found inside Scan into
// these buckets and only emits the safe, unconditional triggers. Patterns
// that are dropped because they are gates, extraction-only, or conditionally
// gated are counted and reported via buildDetectors' summary/-strict check
// rather than silently vanishing.
import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type detPattern struct {
	Src   string `json:"src"`
	Flags string `json:"flags,omitempty"`
}

type detEntry struct {
	ID       string       `json:"id"`
	Severity string       `json:"severity"`
	Keywords []string     `json:"keywords"`
	Patterns []detPattern `json:"patterns"`
}

// Packages whose detection depends on logic the browser can't fa­ithfully
// reproduce (entropy gating, runtime-registered rules, test helpers).
var detectorSkipDirs = map[string]bool{
	"testutil": true,
	"custom":   true,
	"generic":  true,
}

var leadingFlagsRe = regexp.MustCompile(`^\(\?([imsU]+)\)`)

// findMethods are regexp.Regexp methods whose result is a set of matches that
// a detector loops over to build findings — a call to one of these is a
// genuine, match-producing use of the pattern.
var findMethods = map[string]bool{
	"Find":                       true,
	"FindIndex":                  true,
	"FindString":                 true,
	"FindStringIndex":            true,
	"FindSubmatch":               true,
	"FindStringSubmatch":         true,
	"FindSubmatchIndex":          true,
	"FindStringSubmatchIndex":    true,
	"FindAll":                    true,
	"FindAllIndex":               true,
	"FindAllString":              true,
	"FindAllStringIndex":         true,
	"FindAllSubmatch":            true,
	"FindAllStringSubmatch":      true,
	"FindAllSubmatchIndex":       true,
	"FindAllStringSubmatchIndex": true,
}

// gateMethods return a bool and are used to decide *whether* to scan, never
// to produce the matched text a finding is built from.
var gateMethods = map[string]bool{"Match": true, "MatchString": true}

// buildDetectors extracts detector patterns and writes site/js/detectors.js.
// It returns the number of detectors emitted. If strict is true, it fails the
// build when any discovered detector type ends up with zero emitted patterns
// (a silent-loss condition — see the "silent drops" finding in review section
// 28) instead of only printing a warning.
func buildDetectors(root, jsDir string, strict bool) (int, error) {
	detRoot := filepath.Join(root, "internal", "detector")
	fset := token.NewFileSet()
	var entries []detEntry
	var dropped []string

	err := filepath.WalkDir(detRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if detectorSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		ents, drop := extractDetectors(f)
		entries = append(entries, ents...)
		dropped = append(dropped, drop...)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("walk detectors: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	sort.Strings(dropped)

	for _, id := range dropped {
		fmt.Fprintf(os.Stderr, "site-build: WARNING detector %q discovered but emitted zero playground patterns (all references were gates, extraction-only, or conditionally gated)\n", id)
	}
	if len(dropped) > 0 && strict {
		return 0, fmt.Errorf("%d detector(s) emitted zero playground patterns (strict mode): %s", len(dropped), strings.Join(dropped, ", "))
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("marshal detectors: %w", err)
	}
	content := "// Generated by tools/site-build from internal/detector. Do not edit by hand.\n" +
		"window.LW_DETECTORS = " + string(data) + ";\n"
	if err := os.WriteFile(filepath.Join(jsDir, "detectors.js"), []byte(content), 0o644); err != nil {
		return 0, fmt.Errorf("write detectors.js: %w", err)
	}
	return len(entries), nil
}

// extractDetectors returns the emitted entries plus the IDs of any detector
// types discovered in f that ended up with zero safe, unconditional patterns.
func extractDetectors(f *ast.File) (out []detEntry, dropped []string) {
	// Named regexp vars (name -> raw pattern) and every MustCompile literal in
	// the file (covers patterns declared inside slices, used as a fallback).
	varPat := map[string]string{}
	var filePats []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, val := range vs.Values {
				if raw, ok := mustCompileExpr(val); ok && i < len(vs.Names) {
					varPat[vs.Names[i].Name] = raw
				}
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if raw, ok := mustCompileExpr(call); ok {
				filePats = append(filePats, raw)
			}
		}
		return true
	})

	// Group the detector methods by receiver type.
	type methods struct{ id, kw, sev, scan *ast.FuncDecl }
	types := map[string]*methods{}
	getType := func(name string) *methods {
		if types[name] == nil {
			types[name] = &methods{}
		}
		return types[name]
	}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 {
			continue
		}
		rt := recvTypeName(fd.Recv.List[0].Type)
		if rt == "" {
			continue
		}
		switch fd.Name.Name {
		case "ID":
			getType(rt).id = fd
		case "Keywords":
			getType(rt).kw = fd
		case "Severity":
			getType(rt).sev = fd
		case "Scan":
			getType(rt).scan = fd
		}
	}

	for _, m := range types {
		if m.id == nil {
			continue
		}
		id := returnStringLit(m.id)
		if id == "" {
			continue
		}
		entry := detEntry{ID: id, Severity: severityOf(m.sev), Keywords: stringLitsIn(m.kw)}
		if entry.Keywords == nil {
			entry.Keywords = []string{}
		}

		var pats []string
		if m.scan != nil {
			refs := newPatternRefSet()
			collectPatternRefs(m.scan.Body.List, false, refs)
			if len(refs.order) == 0 {
				// Scan never references a known pattern var by name directly
				// (e.g. it delegates entirely to a helper); fall back to
				// every pattern declared in the file, as before.
				pats = filePats
			} else {
				// Iterate in first-reference (source) order, not map order,
				// so the emitted pattern list — and therefore detectors.js —
				// is deterministic across generator runs.
				for _, name := range refs.order {
					if !refs.m[name].trigger {
						continue // gate-only, extraction-only, or conditionally gated
					}
					if p, ok := varPat[name]; ok {
						pats = append(pats, p)
					}
				}
			}
		}

		seen := map[string]bool{}
		for _, p := range dedup(pats) {
			src, flags, ok := goToJSRegex(p)
			if !ok || seen[src+"\x00"+flags] {
				continue
			}
			seen[src+"\x00"+flags] = true
			entry.Patterns = append(entry.Patterns, detPattern{Src: src, Flags: flags})
		}
		if len(entry.Patterns) > 0 {
			out = append(out, entry)
		} else {
			dropped = append(dropped, id)
		}
	}
	return out, dropped
}

// patternRefs accumulates how a pattern var was referenced across Scan.
type patternRefs struct {
	trigger bool // seen as the receiver of a Find*-family call, unconditionally
}

// patternRefSet tracks pattern-var references in first-encounter (source)
// order, so callers that only care about "safe triggers" can still produce a
// deterministic pattern list — a plain map would iterate in random order and
// make detectors.js non-reproducible between generator runs.
type patternRefSet struct {
	m     map[string]*patternRefs
	order []string
}

func newPatternRefSet() *patternRefSet {
	return &patternRefSet{m: map[string]*patternRefs{}}
}

func (s *patternRefSet) ref(name string) *patternRefs {
	if s.m[name] == nil {
		s.m[name] = &patternRefs{}
		s.order = append(s.order, name)
	}
	return s.m[name]
}

// collectPatternRefs walks stmts (a statement list from Scan's body, or a
// nested block) recording how each package-level pattern var is used. cond
// is true when stmts only run conditionally relative to the start of Scan
// (i.e. inside the body/else of an `if`) — a match-producing call found only
// under cond=true is not safe to treat as an unconditional trigger and is
// left unmarked, so it never causes trigger to become true.
func collectPatternRefs(stmts []ast.Stmt, cond bool, refs *patternRefSet) {
	for _, s := range stmts {
		walkStmt(s, cond, refs)
	}
}

func walkStmt(s ast.Stmt, cond bool, refs *patternRefSet) {
	if s == nil {
		return
	}
	switch st := s.(type) {
	case *ast.IfStmt:
		if st.Init != nil {
			walkStmt(st.Init, cond, refs)
		}
		walkExpr(st.Cond, cond, refs)
		collectPatternRefs(st.Body.List, true, refs)
		if st.Else != nil {
			walkStmt(st.Else, true, refs)
		}
	case *ast.BlockStmt:
		collectPatternRefs(st.List, cond, refs)
	case *ast.ForStmt:
		if st.Init != nil {
			walkStmt(st.Init, cond, refs)
		}
		if st.Cond != nil {
			walkExpr(st.Cond, cond, refs)
		}
		if st.Post != nil {
			walkStmt(st.Post, cond, refs)
		}
		collectPatternRefs(st.Body.List, cond, refs)
	case *ast.RangeStmt:
		walkExpr(st.X, cond, refs)
		collectPatternRefs(st.Body.List, cond, refs)
	case *ast.AssignStmt:
		for _, e := range st.Rhs {
			walkExpr(e, cond, refs)
		}
		for _, e := range st.Lhs {
			walkExpr(e, cond, refs)
		}
	case *ast.ExprStmt:
		walkExpr(st.X, cond, refs)
	case *ast.ReturnStmt:
		for _, e := range st.Results {
			walkExpr(e, cond, refs)
		}
	case *ast.DeclStmt:
		genericStmtFallback(st, cond, refs)
	case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
		genericStmtFallback(st, cond, refs)
	default:
		genericStmtFallback(st, cond, refs)
	}
}

// genericStmtFallback handles statement kinds without bespoke conditional
// tracking (rare in these detectors) by generically visiting every call/ident
// at the current conditionality, erring toward not over-crediting a pattern
// as an unconditional trigger.
func genericStmtFallback(n ast.Node, cond bool, refs *patternRefSet) {
	ast.Inspect(n, func(inner ast.Node) bool {
		if call, ok := inner.(*ast.CallExpr); ok {
			classifyCall(call, cond, refs)
		}
		return true
	})
}

func walkExpr(e ast.Expr, cond bool, refs *patternRefSet) {
	if e == nil {
		return
	}
	switch ex := e.(type) {
	case *ast.CallExpr:
		classifyCall(ex, cond, refs)
	case *ast.UnaryExpr:
		walkExpr(ex.X, cond, refs)
	case *ast.BinaryExpr:
		walkExpr(ex.X, cond, refs)
		walkExpr(ex.Y, cond, refs)
	case *ast.ParenExpr:
		walkExpr(ex.X, cond, refs)
	case *ast.SelectorExpr:
		walkExpr(ex.X, cond, refs)
	case *ast.IndexExpr:
		walkExpr(ex.X, cond, refs)
		walkExpr(ex.Index, cond, refs)
	case *ast.SliceExpr:
		walkExpr(ex.X, cond, refs)
	case *ast.StarExpr:
		walkExpr(ex.X, cond, refs)
	case *ast.KeyValueExpr:
		walkExpr(ex.Value, cond, refs)
	case *ast.CompositeLit:
		for _, el := range ex.Elts {
			walkExpr(el, cond, refs)
		}
	case *ast.Ident:
		// A bare identifier reference outside any call (e.g. assigned
		// directly) is neither a trigger nor an argument use; nothing to
		// record — only classifyCall marks roles.
	default:
		ast.Inspect(e, func(inner ast.Node) bool {
			if call, ok := inner.(*ast.CallExpr); ok {
				classifyCall(call, cond, refs)
			}
			return true
		})
	}
}

// classifyCall inspects a single call expression and records the role(s) it
// establishes for any pattern-var identifiers it involves, then recurses into
// its receiver/args at the same conditionality.
func classifyCall(call *ast.CallExpr, cond bool, refs *patternRefSet) {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if recv, ok := sel.X.(*ast.Ident); ok {
			switch {
			case findMethods[sel.Sel.Name] && !cond:
				refs.ref(recv.Name).trigger = true
			case findMethods[sel.Sel.Name], gateMethods[sel.Sel.Name]:
				refs.ref(recv.Name) // recorded, but not a trigger
			default:
				walkExpr(sel.X, cond, refs)
			}
		} else {
			walkExpr(sel.X, cond, refs)
		}
	} else {
		walkExpr(call.Fun, cond, refs)
	}
	for _, a := range call.Args {
		if id, ok := a.(*ast.Ident); ok {
			refs.ref(id.Name) // argument-only use; not a trigger
			continue
		}
		walkExpr(a, cond, refs)
	}
}

// mustCompileExpr reports whether expr is regexp.MustCompile(<string expr>)
// and returns the unquoted pattern. <string expr> may be a plain string
// literal or a chain of literals joined by `+` (a common way to lay out long
// patterns across multiple lines, e.g. dbconn's adonetPattern) — both forms
// are resolved via concatStringLit so neither is silently dropped.
func mustCompileExpr(expr ast.Expr) (string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "MustCompile" {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "regexp" || len(call.Args) != 1 {
		return "", false
	}
	return concatStringLit(call.Args[0])
}

// concatStringLit resolves an expression made up of string literals joined by
// `+` into a single string. It reports false for anything else (e.g. a
// non-literal identifier/const reference), so such patterns are cleanly
// skipped rather than mis-resolved.
func concatStringLit(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		left, ok := concatStringLit(v.X)
		if !ok {
			return "", false
		}
		right, ok := concatStringLit(v.Y)
		if !ok {
			return "", false
		}
		return left + right, true
	case *ast.ParenExpr:
		return concatStringLit(v.X)
	default:
		return "", false
	}
}

func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return ""
}

func returnStringLit(fd *ast.FuncDecl) string {
	if fd == nil || fd.Body == nil {
		return ""
	}
	var out string
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return true
		}
		if lit, ok := ret.Results[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil && out == "" {
				out = s
			}
		}
		return true
	})
	return out
}

func stringLitsIn(fd *ast.FuncDecl) []string {
	if fd == nil || fd.Body == nil {
		return nil
	}
	var out []string
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				out = append(out, s)
			}
		}
		return true
	})
	return out
}

func severityOf(fd *ast.FuncDecl) string {
	if fd == nil || fd.Body == nil {
		return "medium"
	}
	out := "medium"
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && x.Name == "finding" && strings.HasPrefix(sel.Sel.Name, "Severity") {
			out = strings.ToLower(strings.TrimPrefix(sel.Sel.Name, "Severity"))
			return false
		}
		return true
	})
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// goToJSRegex normalizes a Go RE2 pattern for JavaScript and reports whether it
// is safe to use. It lifts leading inline flags into JS flags, rewrites named
// groups and Go-only anchors, and rejects patterns needing Unicode property
// escapes (which would require the 'u' flag and change escaping semantics) or
// the Go-only (?U) ungreedy flag, which has no single-flag JavaScript
// equivalent (it swaps greedy/lazy quantifier semantics for the whole
// pattern) and must not be silently dropped, since that would change match
// semantics without warning.
func goToJSRegex(p string) (src, flags string, ok bool) {
	if m := leadingFlagsRe.FindStringSubmatch(p); m != nil {
		for _, c := range m[1] {
			switch c {
			case 'i', 'm', 's':
				if !strings.ContainsRune(flags, c) {
					flags += string(c)
				}
			case 'U':
				// No JS equivalent for Go's ungreedy flag; reject the whole
				// pattern rather than emit one with different match
				// semantics than the Go source.
				return "", "", false
			}
		}
		p = p[len(m[0]):]
	}
	p = strings.ReplaceAll(p, "(?P<", "(?<")
	p = strings.ReplaceAll(p, `\A`, "^")
	p = strings.ReplaceAll(p, `\z`, "$")
	p = strings.ReplaceAll(p, `\Z`, "$")
	if strings.Contains(p, `\p{`) || strings.Contains(p, `\P{`) || strings.Contains(p, "(?P=") {
		return "", "", false
	}
	return p, flags, true
}
