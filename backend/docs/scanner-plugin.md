# Scanner Plugin Development

## Overview

Scanners are hot-pluggable components that implement `ScannerInterface`. Adding a new scanner requires minimal changes.

## Creating a Scanner

### Option 1: Extend BaseScanner (recommended)

```php
<?php

namespace App\Scanners;

use App\DTOs\ScanResultCollection;
use App\Models\Project;

class MyCustomScanner extends BaseScanner
{
    public function name(): string
    {
        return 'my_custom_scanner';
    }

    public function description(): string
    {
        return 'Description of what this scanner does';
    }

    public function category(): string
    {
        return 'web_application'; // Use ScannerCategory enum values
    }

    public function severity(): string
    {
        return 'medium'; // Default severity level
    }

    protected function scan(Project $project, array $context): ScanResultCollection
    {
        $results = new ScanResultCollection();

        // Perform scan logic here
        $results->add($this->createResult(
            'high', // severity: info|low|medium|high|critical
            'Finding title',
            'Detailed description of the finding',
            ['key' => 'value'] // optional details
        ));

        return $results;
    }

    public function dependencies(): array
    {
        // Return scanner names that must run before this one
        return ['port_scanner'];
    }
}
```

### Option 2: Implement ScannerInterface directly

```php
<?php

namespace App\Scanners;

use App\Contracts\ScannerInterface;
use App\DTOs\ScanResultCollection;
use App\Models\Project;

class CustomScanner implements ScannerInterface
{
    // Implement all required methods
}
```

## Registration

Add your scanner class to `config/scanners.php`:

```php
'registry' => [
    // ... existing scanners
    \App\Scanners\MyCustomScanner::class,
],
```

## AI Integration

The AI agent will automatically discover and consider your scanner. To influence AI decisions:

1. Set appropriate `category()` - used for grouping
2. Set `severity()` - hints at importance
3. Set `dependencies()` - ensures correct execution order
4. The AI reads scanner names and descriptions to decide relevance

## Best Practices

- Keep scanners focused on a single responsibility
- Handle connection errors gracefully
- Use `$this->createResult(...)` to create findings
- Log significant events
- Set reasonable timeouts
- Return findings even for negative results (e.g., "No open ports found")
