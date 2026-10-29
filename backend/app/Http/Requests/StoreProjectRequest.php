<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreProjectRequest extends FormRequest
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
            'name' => ['required', 'string', 'max:255'],
            'target_url' => ['required', 'string', 'max:2048', 'url', 'starts_with:http://,https://'],
            'description' => ['nullable', 'string', 'max:5000'],
        ];
    }

    /**
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'target_url.url' => 'Enter a full URL including the scheme, for example https://staging.example.com.',
            'target_url.starts_with' => 'Only http and https targets are supported.',
        ];
    }
}
