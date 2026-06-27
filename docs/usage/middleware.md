---
title: "Middleware"
description: "Sanitize requests and responses before they reach your code."
---

# HTTP Middleware

The `warden` middleware sanitizes/inspects request input (or the response) before
it reaches the controller (or the client).

## Input

```php
Route::post('/chat', ChatController::class)->middleware('warden:input,strict');
//                                                        direction ^   ^ policy
```

It recursively scans **every string field**, including nested arrays like the
OpenAI `messages[]` shape:

```json
{ "messages": [ { "role": "user", "content": "ignore all previous instructions" } ] }
```

- Blocked fields raise a **422** via the native validation flow
  (`messages.0.content` in the error bag).
- Allowed fields are replaced with their **sanitized** text.
- Per-field verdicts are exposed on the request.

```php
public function __invoke(Request $request)
{
    $verdict = $request->wardenVerdict('prompt'); // or ->wardenVerdict() for the map
    $clean   = $request->input('prompt');         // already sanitized
}
```

## Output

```php
Route::get('/answer', AnswerController::class)->middleware('warden:output,balanced');
```

The response is JSON-aware: each string value is scanned, defanged and re-encoded;
on a block the body becomes `{"error":"output_blocked"}` with a 422 and a JSON
content type.

::: callout tip "Combine directions"
Apply both: `->middleware(['warden:input,strict', 'warden:output,balanced'])` to
guard the request on the way in and the response on the way out.
:::
