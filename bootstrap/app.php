<?php

declare(strict_types=1);

use App\Exceptions\ApiExceptionHandler;
use App\Http\Middleware\AcceptApplicationJsonHeader;
use App\Http\Middleware\WorkOSTokenMiddleware;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        apiPrefix: 'api/v1',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->append(AcceptApplicationJsonHeader::class);
        $middleware->alias([
            'auth.token' => WorkOSTokenMiddleware::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        $exceptions->render(function (Throwable $e, Request $request) {
            return ApiExceptionHandler::handle($e, $request);
        });
    })->create();
