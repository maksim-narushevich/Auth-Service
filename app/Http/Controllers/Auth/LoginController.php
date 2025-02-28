<?php

declare(strict_types=1);

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use WorkOS\Exception\WorkOSException;
use WorkOS\Resource\AuthenticationResponse;
use WorkOS\UserManagement;
use WorkOS\WorkOS;

final class LoginController extends Controller
{
    /**
     * @OA\Post(
     *     path="/auth/login",
     *     summary="Login user",
     *     description="Login user via email and password",
     *     operationId="authLogin",
     *     tags={"Auth"},
     *
     *     @OA\RequestBody(
     *
     *         @OA\MediaType(
     *             mediaType="application/json",
     *
     *             @OA\Schema(
     *
     *                 @OA\Property(
     *                     property="email",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="password",
     *                     type="string"
     *                 ),
     *                 example={"email": "test@test.com", "password": "password"}
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(response=200, description="Successful operation"),
     *     @OA\Response(response=401, description="Unauthenticated"),
     *     @OA\Response(response=400, description="Bad request")
     * )
     *
     * @throws AuthenticationException
     */
    public function __invoke(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required_without:auth_provider'],
            'auth_provider' => ['in:workos'],
        ]);

        WorkOS::setApiKey(config('workos.api_key'));
        WorkOS::setClientId(config('workos.client_id'));

        $userManagement = new UserManagement;

        try {
            $authResponse = $userManagement->authenticateWithPassword(
                clientId: config('workos.client_id'),
                email: $validated['email'],
                password: $validated['password'],
            );
        } catch (WorkOSException $e) {
            throw new AuthenticationException($e->responseMessage ?? $e->getMessage());
        }

        $workOSUser = $authResponse->user;

        $user = User::query()->where('email', $workOSUser->email)->first();

        if ($user === null) {
            throw new AuthenticationException;
        }

        return $this->respondWithToken($authResponse);
    }

    protected function respondWithToken(AuthenticationResponse $authResponse): JsonResponse
    {
        return response()->json([
            'access_token' => $authResponse->access_token,
            'refresh_token' => $authResponse->refresh_token,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 60,
        ]);
    }
}
