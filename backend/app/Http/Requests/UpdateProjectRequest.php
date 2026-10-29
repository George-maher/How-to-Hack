<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateProjectRequest extends FormRequest
{
    public function authorize(): bool
    {
        // The policy is checked by the controller; this only distinguishes an
        // authenticated caller from an anonymous one.
        return $this->user() !== null;
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'name' => ['sometimes', 'string', 'max:255'],
            'target_url' => ['sometimes', 'string', 'max:2048', 'url', 'starts_with:http://,https://'],
            'description' => ['sometimes', 'nullable', 'string', 'max:5000'],
            'status' => ['sometimes', 'string', 'in:active,inactive'],
        ];
    }
}
