<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

/**
 * Options for starting a scan.
 *
 * `tools` is a *request*, not a grant: the server intersects it with the
 * registry and the resulting plan still needs explicit approval when it
 * contains any active scanner.
 */
class InitiateScanRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user() !== null;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'tools' => ['sometimes', 'array', 'max:30'],
            'tools.*' => ['string', 'max:64'],
            'ports' => ['sometimes', 'array', 'max:20'],
            'ports.*' => ['integer', 'min:1', 'max:65535'],
            'max_scanners' => ['sometimes', 'integer', 'min:1', 'max:20'],
            'notes' => ['sometimes', 'nullable', 'string', 'max:500'],
        ];
    }
}
