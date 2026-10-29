<?php

declare(strict_types=1);

/**
 * Static wiring verification: routes, imports and constructor dependencies.
 *
 * Laravel cannot boot in this environment (no vendor tree), but the two things
 * that break a boot can still be checked without running it:
 *
 *   1. a route pointing at a controller action that does not exist;
 *   2. a constructor argument the container cannot resolve (a concrete class
 *      with no file, or an interface with no binding).
 *
 * This is a static analysis of the source, not a runtime proof. It is
 * deliberately conservative: it fails on anything it cannot resolve, so an
 * unknown type is reported rather than ignored.
 *
 *     php backend/tests/Standalone/container_wiring_test.php
 */

$root = dirname(__DIR__, 2);
$appDir = $root.'/app';

$passed = 0;
$failed = 0;
$failures = [];

function check(string $label, bool $condition, string $context = ''): void
{
    global $passed, $failed, $failures;

    if ($condition) {
        $passed++;

        return;
    }

    $failed++;
    $failures[] = $label.($context !== '' ? ' — '.$context : '');
}

/**
 * Extract the type names of constructor parameters.
 *
 * A type is the run of name tokens immediately before a T_VARIABLE. Anything
 * after it (default values such as `null`, `false`, `[]`) is not a dependency.
 *
 * @return list<string>
 */
function constructorTypes(array $tokens, int $functionIndex): array
{
    $types = [];
    $run = [];
    $inSignature = false;
    $union = false;

    for ($j = $functionIndex + 1; $j < count($tokens); $j++) {
        $next = $tokens[$j];

        if (is_string($next)) {
            if ($next === '(' && ! $inSignature) {
                $inSignature = true;

                continue;
            }
            if ($next === ')') {
                break;
            }
            if ($next === '|' || $next === '&') {
                $union = true;

                continue;
            }
            if ($next === ',') {
                $run = [];

                continue;
            }

            continue;
        }

        if (! $inSignature) {
            continue;
        }

        if ($next[0] === T_VARIABLE) {
            foreach ($run as $candidate) {
                if (! in_array(strtolower($candidate), ['public', 'protected', 'private', 'readonly', 'array', 'string', 'int', 'float', 'bool', 'mixed', 'callable', 'iterable', 'object', 'self', 'static', 'null', 'false', 'true'], true)) {
                    $types[] = $candidate;
                }
            }
            $run = [];
            $union = false;

            continue;
        }

        if (in_array($next[0], [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true)) {
            $run[] = ltrim($next[1], '?');
        }
    }

    return array_values(array_unique($types));
}

/**
 * Tokenise a PHP file into the facts this analysis needs.
 *
 * @return array{namespace: string, imports: array<string,string>, classes: array<string,array{methods: list<string>, ctor: list<string>}>}
 */
function parseFile(string $path): array
{
    $tokens = token_get_all(file_get_contents($path));
    $namespace = '';
    $imports = [];
    $classes = [];

    $depth = 0;
    $current = null;
    $pendingCtor = false;

    for ($i = 0; $i < count($tokens); $i++) {
        $token = $tokens[$i];

        if (is_string($token)) {
            if ($token === '{') {
                $depth++;
            } elseif ($token === '}') {
                $depth--;
                if ($depth <= 0) {
                    $current = null;
                }
            } elseif ($token === ')' && $pendingCtor) {
                $pendingCtor = false;
            }

            continue;
        }

        [$id, $text] = $token;

        // `"{$x}"` opens a brace with T_CURLY_OPEN; its closing '}' arrives as
        // a plain character token. Count the opener so the pair balances.
        if ($id === T_CURLY_OPEN || (defined('T_DOLLAR_OPEN_CURLY_BRACES') && $id === T_DOLLAR_OPEN_CURLY_BRACES)) {
            $depth++;

            continue;
        }

        if ($id === T_NAMESPACE) {
            $name = '';
            for ($j = $i + 1; $j < count($tokens); $j++) {
                $next = $tokens[$j];
                if (is_string($next)) {
                    if ($next === ';' || $next === '{') {
                        break;
                    }

                    continue;
                }
                if (in_array($next[0], [T_STRING, T_NAME_QUALIFIED, T_NS_SEPARATOR], true)) {
                    $name .= $next[1];
                }
            }
            $namespace = trim($name, '\\');

            continue;
        }

        // Top-level `use` only: imports, never trait use or closures.
        if ($id === T_USE && $depth === 0 && $current === null) {
            $name = '';
            for ($j = $i + 1; $j < count($tokens); $j++) {
                $next = $tokens[$j];
                if (is_string($next)) {
                    break;
                }
                if ($next[0] === T_AS) {
                    break;
                }
                if (in_array($next[0], [T_STRING, T_NAME_QUALIFIED, T_NS_SEPARATOR], true)) {
                    $name .= $next[1];
                }
            }
            $name = trim($name, '\\');
            if ($name !== '') {
                $position = strrpos($name, '\\');
                $short = $position === false ? $name : substr($name, $position + 1);
                $imports[$short] = $name;
            }

            continue;
        }

        if (in_array($id, [T_CLASS, T_INTERFACE, T_TRAIT, T_ENUM], true)) {
            // Skip `::class` constants and anonymous classes.
            $previous = $tokens[$i - 1] ?? null;
            $isConstant = is_array($previous) && $previous[0] === T_DOUBLE_COLON;
            $isAnonymous = is_array($previous) && $previous[0] === T_NEW;
            $isEnumCase = $id === T_ENUM && is_array($previous) && in_array($previous[0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON], true);

            if ($isConstant || $isAnonymous || $isEnumCase) {
                continue;
            }

            for ($j = $i + 1; $j < count($tokens); $j++) {
                if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
                    $current = $tokens[$j][1];
                    $classes[$current] = ['methods' => [], 'public' => [], 'ctor' => []];
                    break;
                }
            }

            continue;
        }

        if ($id === T_FUNCTION && $current !== null) {
            $name = null;
            for ($j = $i + 1; $j < count($tokens); $j++) {
                $next = $tokens[$j];
                if (is_string($next)) {
                    break;
                }
                if ($next[0] === T_STRING) {
                    $name = $next[1];
                    break;
                }
            }

            if ($name !== null) {
                $classes[$current]['methods'][] = $name;
                $classes[$current]['public'] ??= [];

                // Visibility precedes `function`; anything unmarked is public.
                $visibility = 'public';
                for ($k = $i - 1, $seen = 0; $k >= 0 && $seen < 6; $k--, $seen++) {
                    $prev = $tokens[$k];
                    if (is_array($prev) && in_array($prev[0], [T_PUBLIC, T_PRIVATE, T_PROTECTED], true)) {
                        $visibility = strtolower($prev[1]);
                        break;
                    }
                }

                if ($visibility === 'public') {
                    $classes[$current]['public'][] = $name;
                }
            }

            if ($name === '__construct') {
                $classes[$current]['ctor'] = constructorTypes($tokens, $i);
                $pendingCtor = true;
            }
        }
    }

    return ['namespace' => $namespace, 'imports' => $imports, 'classes' => $classes];
}

// ---------------------------------------------------------------------------
// Index the application
// ---------------------------------------------------------------------------
$files = [];
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($appDir, FilesystemIterator::SKIP_DOTS));
foreach ($iterator as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
        $files[] = $file->getPathname();
    }
}
sort($files);

/** @var array<string, string> $classFile FQCN => path */
$classFile = [];
/** @var array<string, array{methods: list<string>, ctor: list<string>}> $classInfo */
$classInfo = [];
/** @var array<string, array<string,string>> $importsByFile */
$importsByFile = [];

foreach ($files as $path) {
    $parsed = parseFile($path);
    $importsByFile[$path] = $parsed['imports'];

    foreach ($parsed['classes'] as $name => $info) {
        $fqcn = $parsed['namespace'] !== '' ? $parsed['namespace'].'\\'.$name : $name;
        $classFile[$fqcn] = $path;
        $classInfo[$fqcn] = $info;
    }
}

// routes/api.php is outside app/, so index it separately for alias resolution.
$routeFiles = [$root.'/routes/api.php'];
foreach ($routeFiles as $path) {
    if (is_file($path)) {
        $importsByFile[$path] = parseFile($path)['imports'];
    }
}

check('the application index is populated', count($classFile) > 100, count($classFile).' classes; e.g. '.implode(', ', array_slice(array_keys($classFile), 0, 3)));

// ---------------------------------------------------------------------------
// 1. Every `use App\...` import resolves to a real file
// ---------------------------------------------------------------------------
$dangling = [];
foreach ($importsByFile as $path => $imports) {
    foreach ($imports as $fqcn) {
        if (str_starts_with($fqcn, 'App\\') && ! isset($classFile[$fqcn])) {
            $dangling[] = str_replace($root.'/', '', $path).' imports '.$fqcn;
        }
    }
}
check('no import points at a missing class', $dangling === [], implode('; ', array_slice($dangling, 0, 5)));

// ---------------------------------------------------------------------------
// 2. Every route points at a controller action that exists
// ---------------------------------------------------------------------------
$routeFile = $root.'/routes/api.php';
$routes = file_get_contents($routeFile);
$routeImports = $importsByFile[$routeFile] ?? [];

preg_match_all("/\[([A-Za-z_][A-Za-z0-9_]*)::class,\s*'([A-Za-z0-9_]+)'\]/", $routes, $matches, PREG_SET_ORDER);

check('routes reference controller actions', count($matches) > 10, count($matches).' actions');

$missingRoutes = [];
$routeActions = [];
foreach ($matches as [, $alias, $method]) {
    $fqcn = $routeImports[$alias] ?? null;

    if ($fqcn === null || ! isset($classFile[$fqcn])) {
        $missingRoutes[] = "{$alias}::{$method} (no such class)";

        continue;
    }

    $routeActions[] = $fqcn.'@'.$method;

    if (in_array($method, $classInfo[$fqcn]['methods'] ?? [], true)
        && ! in_array($method, $classInfo[$fqcn]['public'] ?? [], true)) {
        $missingRoutes[] = "{$alias}::{$method} (not public)";

        continue;
    }

    if (! in_array($method, $classInfo[$fqcn]['methods'] ?? [], true)) {
        // A method inherited from a parent controller is legitimate.
        $parent = null;
        $source = file_get_contents($classFile[$fqcn]);
        if (preg_match('/class\s+\w+\s+extends\s+([A-Za-z_\\\\][A-Za-z0-9_\\\\]*)/', $source, $m)) {
            $parent = $m[1];
        }

        $found = false;
        if ($parent !== null && isset($classInfo[$parent])) {
            $found = in_array($method, $classInfo[$parent]['methods'], true);
        }

        if (! $found) {
            $missingRoutes[] = "{$alias}::{$method} (method not defined)";
        }
    }
}

preg_match_all("/Route::apiResource\(\s*'[^']+',\s*([A-Za-z_][A-Za-z0-9_]*)::class/", $routes, $resourceMatches);
foreach ($resourceMatches[1] as $alias) {
    $fqcn = $routeImports[$alias] ?? null;
    if ($fqcn === null) {
        continue;
    }
    foreach (['index', 'store', 'show', 'update', 'destroy'] as $method) {
        $routeActions[] = $fqcn.'@'.$method;
        if (in_array($method, $classInfo[$fqcn]['methods'] ?? [], true)
        && ! in_array($method, $classInfo[$fqcn]['public'] ?? [], true)) {
        $missingRoutes[] = "{$alias}::{$method} (not public)";

        continue;
    }

    if (! in_array($method, $classInfo[$fqcn]['methods'] ?? [], true)) {
            $missingRoutes[] = "{$alias}::{$method} (apiResource, method not defined)";
        }
    }
}

check('every route action resolves to a defined method', $missingRoutes === [], implode('; ', $missingRoutes));

// Every public controller action should be reachable from a route (dead
// actions are not a security bug, but they often mean a broken route).
$controllerActions = [];
foreach ($classInfo as $fqcn => $info) {
    if (str_starts_with($fqcn, 'App\\Http\\Controllers\\')) {
        foreach ($info['public'] ?? [] as $method) {
            if (! str_starts_with($method, '__')) {
                $controllerActions[] = $fqcn.'@'.$method;
            }
        }
    }
}
$unrouted = array_values(array_diff($controllerActions, $routeActions));
check(
    'no controller action is unreachable',
    $unrouted === [],
    'unrouted: '.implode(', ', $unrouted),
);

// ---------------------------------------------------------------------------
// 3. Constructor dependencies resolve (concrete → file, interface → binding)
// ---------------------------------------------------------------------------
$bindings = [];
foreach ($classFile as $fqcn => $path) {
    if (! str_contains($path, '/Providers/')) {
        continue;
    }

    $source = file_get_contents($path);

    // bind(Iface::class, Impl::class) and singleton(X::class)
    preg_match_all('/(?:bind|singleton)\(\s*([A-Za-z0-9_\\\\]+)::class(?:\s*,\s*([A-Za-z0-9_\\\\]+)::class)?/', $source, $binds, PREG_SET_ORDER);
    $imports = $importsByFile[$path] ?? [];

    foreach ($binds as $bind) {
        $resolve = static function (string $short) use ($imports): string {
            return $imports[$short] ?? $short;
        };
        $abstract = $resolve($bind[1]);
        $concrete = isset($bind[2]) && $bind[2] !== '' ? $resolve($bind[2]) : $abstract;
        $bindings[$abstract] = $concrete;
    }
}

check('service providers register bindings', $bindings !== [], count($bindings).' bindings');

// Types Laravel resolves itself; injecting these is normal.
$frameworkTypes = static fn (string $type): bool =>
    str_starts_with($type, 'Illuminate\\')
    || str_starts_with($type, 'Psr\\')
    || str_starts_with($type, 'Closure')
    || in_array(strtolower($type), ['array', 'string', 'int', 'float', 'bool', 'mixed', 'callable', 'iterable', 'object', 'self', 'static'], true);

$unresolved = [];
$checked = 0;

// Global classes PHP already provides; injecting them is not a wiring problem.
$globalTypes = ['datetimeimmutable', 'datetimeinterface', 'datetime', 'throwable', 'exception', 'generator', 'stdclass', 'closure', 'arrayaccess', 'countable', 'stringable', 'jsonserializable'];

$resolveType = static function (string $type, array $imports, string $namespace) use (&$classFile, &$bindings, $frameworkTypes, $globalTypes): ?string {
    $type = ltrim($type, '?');

    if ($frameworkTypes($type) || in_array(strtolower($type), $globalTypes, true)) {
        return null;
    }

    // A leading backslash is an explicit FQCN: never namespace-relative.
    if (str_starts_with($type, '\\')) {
        $fqcn = ltrim($type, '\\');

        if (isset($classFile[$fqcn])) {
            return $fqcn;
        }
        if (isset($bindings[$fqcn])) {
            return $bindings[$fqcn];
        }

        return str_starts_with($fqcn, 'App\\') ? $fqcn : null;
    }

    // Imported alias, then same namespace, then a literal class name.
    $candidates = array_filter([$imports[$type] ?? null, $namespace.'\\'.$type, $type]);

    foreach ($candidates as $candidate) {
        if (isset($classFile[$candidate])) {
            return $candidate;
        }
        if (isset($bindings[$candidate])) {
            return $bindings[$candidate];
        }
    }

    return $type;
};

foreach ($classInfo as $fqcn => $info) {
    if ($info['ctor'] === []) {
        continue;
    }

    $imports = $importsByFile[$classFile[$fqcn]] ?? [];
    $declaringNamespace = substr($fqcn, 0, (int) strrpos($fqcn, '\\'));

    foreach ($info['ctor'] as $type) {
        // Skip constructor-promoted visibility keywords that tokenise as strings.
        if (in_array(strtolower($type), ['public', 'protected', 'private', 'readonly'], true)) {
            continue;
        }

        $resolved = $resolveType($type, $imports, $declaringNamespace);

        if ($resolved === null) {
            continue;
        }

        $checked++;

        if (! isset($classFile[$resolved]) && ! isset($bindings[$resolved])) {
            $unresolved[] = $fqcn.' needs '.$type;
        }
    }
}

check('constructor dependencies resolve', $unresolved === [], implode('; ', array_slice(array_unique($unresolved), 0, 8)));
check('a meaningful number of dependencies were checked', $checked > 40, $checked.' parameters');

// ---------------------------------------------------------------------------
// 4. Interfaces that are injected are bound
// ---------------------------------------------------------------------------
$contracts = [];
foreach ($classFile as $fqcn => $path) {
    if (str_starts_with($fqcn, 'App\\Contracts\\')) {
        $contracts[] = $fqcn;
    }
}
check('contracts exist', $contracts !== [], count($contracts).' contracts');

$injectedContracts = [];
foreach ($classInfo as $fqcn => $info) {
    foreach ($info['ctor'] as $type) {
        $imports = $importsByFile[$classFile[$fqcn]] ?? [];
        $fqcnType = $imports[$type] ?? ('App\\Contracts\\'.$type);
        if (in_array($fqcnType, $contracts, true)) {
            $injectedContracts[$fqcnType][] = $fqcn;
        }
    }
}

$unbound = [];
foreach (array_keys($injectedContracts) as $contract) {
    if (! isset($bindings[$contract])) {
        $unbound[] = $contract.' injected by '.implode(', ', $injectedContracts[$contract]);
    }
}
check('every injected contract is bound', $unbound === [], implode('; ', $unbound));

// ---------------------------------------------------------------------------
// 5. Semantic singletons that must stay singletons
// ---------------------------------------------------------------------------
$mustBeSingletons = [
    'App\\Security\\Http\\SafeHttpClient',
    'App\\Services\\Security\\AuditLogger',
    'App\\Services\\Security\\TargetScopeService',
    'App\\Services\\Security\\ApprovalService',
    'App\\Services\\Runner\\RunnerClient',
];

$notSingleton = [];
$shortName = static fn (string $fqcn): string => substr($fqcn, (int) strrpos('\\'.$fqcn, '\\'));

foreach ($mustBeSingletons as $service) {
    if (! isset($classFile[$service])) {
        $notSingleton[] = $service.' (missing file)';

        continue;
    }

    $bound = false;
    foreach ($classFile as $fqcn => $path) {
        if (! str_contains($path, '/Providers/')) {
            continue;
        }
        $providerSource = file_get_contents($path);
        if (str_contains($providerSource, 'singleton(')
            && str_contains($providerSource, $shortName($service).'::class')) {
            $bound = true;
            break;
        }
    }
    if (! $bound) {
        $notSingleton[] = $service;
    }
}
check('security services are registered as singletons', $notSingleton === [], implode('; ', $notSingleton));

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
echo "\n";
foreach ($failures as $failure) {
    echo "  FAIL: {$failure}\n";
}

printf("static wiring: %d passed, %d failed\n", $passed, $failed);

exit($failed === 0 ? 0 : 1);
