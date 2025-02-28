<?php

declare(strict_types=1);

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;
use WorkOS\UserManagement;
use WorkOS\WorkOS;

final class LogoutController extends Controller
{
    /**
     * @OA\Post(
     *     path="/auth/logout",
     *     summary="Logout auth user",
     *     description="Logout auth user",
     *     operationId="authLogout",
     *     tags={"Auth"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(response=200, description="Successful operation"),
     *     @OA\Response(response=401, description="Unauthenticated")
     * )
     */
    public function __invoke(Request $request): JsonResponse
    {
        $token = $request->bearerToken();

        WorkOS::setApiKey(config('workos.api_key'));
        WorkOS::setClientId(config('workos.client_id'));

        $userManagement = new UserManagement;

        $client = new Client;
        $jwksUrl = $userManagement->getJwksUrl(config('workos.client_id'));
        $response = $client->request('GET', $jwksUrl);
        $jwksJSON = $response->getBody()->getContents();
        $jwks = json_decode($jwksJSON, true);
        $session = JWT::decode($token, JWK::parseKeySet($jwks));
        dump($session->sid);

        $logoutUrl = $userManagement->getLogoutUrl(sessionId: $session->sid);
        $client->request('GET', $logoutUrl);

        $userId = Auth::id();
        Auth::logout();
        DB::table('sessions')->where('user_id', $userId)->delete();

        return response()->json(
            [
                'status' => Response::HTTP_OK,
                'message' => 'Successfully logged out.',
            ]
        );
    }
}
