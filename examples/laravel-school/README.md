# Laravel + HHTTPS — School chat example

A school messaging system where only verified teachers can post announcements.

## Install
```bash
composer require firebase/php-jwt
```

## Wire up
```php
// app/Http/Kernel.php
protected $routeMiddleware = [
    'hhttps' => \App\Http\Middleware\HHTPPSMiddleware::class,
];

// routes/web.php
Route::post('/announcement',
    [AnnouncementController::class, 'store']
)->middleware('hhttps:teacher,86');
```

## Endpoints
| Path | Middleware |
|---|---|
| POST /announcement | hhttps:teacher,86 |
| GET  /announcement/{id} | none |
