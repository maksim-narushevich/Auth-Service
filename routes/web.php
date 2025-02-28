<?php

use App\Http\Controllers\SSO\AuthController;
use App\Livewire\Users\User;
use App\Livewire\Users\UserCreate;
use App\Livewire\Users\UserEdit;
use App\Livewire\Users\UsersList;
use Illuminate\Support\Facades\Route;

Route::group(['as' => 'users.'], function () {
    Route::get('/users/create', UserCreate::class)->name('create');
    Route::get('/users', UsersList::class)->name('index');
    Route::get('/users/{user}', User::class)->name('show');
    Route::get('/users/{user}/edit', UserEdit::class)->name('edit');
});
Route::redirect('/', '/users', 301);

Route::get('/login', function () {
    return redirect(config('workos.redirect_login_url'));
})->name('auth.workos.login');

Route::get('/error', function () {
    return response()->json(['error' => 'Unauthorized'], 401);
})->name('error.page');

Route::get('/auth/workos', [AuthController::class, 'redirectToWorkOS'])->name('auth.workos');
Route::get('/auth/callback', [AuthController::class, 'handleCallback'])->name('auth.callback');
