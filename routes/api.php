<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::controller(AuthController::class)->group(function(){
    Route::post('sendOtp', 'sendOtp');
    Route::post('verify-otp', 'verifyOtp');
    Route::post('register', 'register');
});

Route::middleware(['auth:api'])->group(function(){
    Route::controller(AuthController::class)->group(function(){
        Route::post('logout', 'logout');
        Route::get('profile', 'profile');
        Route::patch('update', 'update');
        Route::get('me', 'me');
    });
});

