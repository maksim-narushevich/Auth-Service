<?php

declare(strict_types=1);

use App\Http\Controllers\Auth\AuthUserInfoController;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\LogoutController;
use App\Http\Controllers\Auth\RefreshTokenController;
use App\Http\Controllers\Auth\ResetPasswordController;
use App\Http\Controllers\Auth\SendPasswordResetLinkController;
use App\Http\Controllers\Auth\VerifyTokenController;
use App\Http\Controllers\DynamoDBController;
use App\Http\Controllers\Permissions\DeletePermissionController;
use App\Http\Controllers\Permissions\ShowPermissionListController;
use App\Http\Controllers\Permissions\StorePermissionController;
use App\Http\Controllers\Roles\AssignUserRoleController;
use App\Http\Controllers\Roles\DeleteRoleController;
use App\Http\Controllers\Roles\RemoveUserRoleController;
use App\Http\Controllers\Roles\ShowRoleListController;
use App\Http\Controllers\Roles\StoreRoleController;
use App\Http\Controllers\User\DeleteUserController;
use App\Http\Controllers\User\ShowUserController;
use App\Http\Controllers\User\ShowUserListController;
use App\Http\Controllers\User\StoreUserController;
use App\Http\Controllers\User\UpdateUserController;
use Illuminate\Support\Facades\Route;

Route::as('api.')->group(function () {
    Route::middleware(['auth:api'])->group(function () {
        Route::prefix('users')->as('users.')->group(function () {
            Route::get('/', ShowUserListController::class)->name('index');
            Route::post('/', StoreUserController::class)->name('store')->withoutMiddleware(['auth:api']);
            Route::get('/{user}', ShowUserController::class)->name('show');
            Route::patch('/{user}', UpdateUserController::class)->name('update');
            Route::delete('/{user}', DeleteUserController::class)->name('destroy');

            Route::post('/{user}/assign-role', AssignUserRoleController::class)->name('assign-user-role');
            Route::post('/{user}/remove-role', RemoveUserRoleController::class)->name('remove-user-role');
        });

        Route::prefix('auth')->as('auth.')->group(function () {
            Route::post('login', LoginController::class)->name('login')->withoutMiddleware(['auth:api']);
            Route::post('logout', LogoutController::class)->name('logout');
            Route::post('refresh', RefreshTokenController::class)->name('refresh');
            Route::post('me', AuthUserInfoController::class)->name('me');
            Route::post('verify', VerifyTokenController::class)->name('verify');
        });

        Route::prefix('roles')->as('roles.')->group(function () {
            Route::get('/', ShowRoleListController::class)->name('index');
            Route::post('/', StoreRoleController::class)->name('store');
            Route::delete('/', DeleteRoleController::class)->name('destroy');
        });

        Route::prefix('permissions')->as('permissions.')->group(function () {
            Route::get('/', ShowPermissionListController::class)->name('index');
            Route::post('/', StorePermissionController::class)->name('store');
            Route::delete('/', DeletePermissionController::class)->name('destroy');
        });

        Route::get('/dynamodb/create-table', [DynamoDBController::class, 'createTable']);
        Route::post('/dynamodb/store', [DynamoDBController::class, 'store']);
        Route::get('/dynamodb/show/{id}', [DynamoDBController::class, 'show']);
        Route::delete('/dynamodb/delete/{id}', [DynamoDBController::class, 'destroy']);
    });

    Route::post('password/send-reset-link', SendPasswordResetLinkController::class)->name('password.send-reset-link');
    Route::post('password/reset', ResetPasswordController::class)->name('password.reset');
});
