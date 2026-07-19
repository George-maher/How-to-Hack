<?php

return [
    'default_provider' => env('AI_AGENT_PROVIDER', 'openai'),

    'providers' => [
        'openai' => [
            'api_key' => env('OPENAI_API_KEY'),
            'model' => env('OPENAI_MODEL', 'gpt-4'),
            'temperature' => (float) env('OPENAI_TEMPERATURE', 0.3),
            'max_tokens' => (int) env('OPENAI_MAX_TOKENS', 2000),
        ],

        'claude' => [
            'api_key' => env('CLAUDE_API_KEY'),
            'model' => env('CLAUDE_MODEL', 'claude-3-opus-20240229'),
            'max_tokens' => (int) env('CLAUDE_MAX_TOKENS', 2000),
        ],

        'openrouter' => [
            'api_key' => env('OPENROUTER_API_KEY'),
            'base_url' => env('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1'),
            'model' => env('OPENROUTER_MODEL', 'openai/gpt-4o'),
            'temperature' => (float) env('OPENROUTER_TEMPERATURE', 0.3),
            'max_tokens' => (int) env('OPENROUTER_MAX_TOKENS', 2000),
        ],
    ],

    'scan_state' => [
        'max_reasoning_history' => (int) env('AI_MAX_REASONING', 100),
        'auto_stop_threshold' => (float) env('AI_AUTO_STOP_THRESHOLD', 0.85),
    ],
];
